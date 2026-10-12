import { createHash } from "node:crypto";
import { readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";
import { artifactInspectionResultSchema } from "../../src/domain/artifactInspection.js";
import {
  artifactInventoryResultSchema,
  artifactExtractionResultSchema,
} from "../../src/domain/artifactGraph.js";
import { parseEvidence } from "../../src/domain/evidence.js";
import { cliTest } from "../support/cli/cliFixture.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";
import { connectLocalToolsMcp } from "../fixtures/localToolsMcp.js";
import { parseMcpToolError } from "../fixtures/mcpToolError.js";
import { inesFixture } from "../fixtures/ines.js";

const inventoryFrom = (input: unknown) => {
  const evidence = parseEvidence(input);
  expect(evidence.subject).toMatchObject({
    format: "ines",
    architecture: null,
  });
  const inspection = artifactInspectionResultSchema.parse(
    evidence.normalized_result,
  );
  expect(inspection.coverage.status).toBe("complete-within-substeps");
  expect(inspection.observations.map(({ kind }) => kind)).toEqual([
    "root-manifest",
    "container-header",
    "reconstruction",
  ]);
  const substep = inspection.substeps[0];
  if (substep === undefined) throw new Error("Missing inventory substep");
  parseEvidence(substep.evidence);
  return artifactInventoryResultSchema.parse(
    substep.evidence.normalized_result,
  );
};

cliTest(
  "classic iNES has the same complete byte inventory through compiled CLI and stdio MCP",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-ines-public-");
    const path = join(root, "卡带.data");
    const bytes = inesFixture({
      trainer: true,
      trailing: Buffer.from([0, 255, 3, 0]),
    });
    await writeFile(path, bytes);
    const cliResult = await cli.run({
      arguments: ["inspect-artifact", path, "--json"],
    });
    expect(cliResult.exitCode, cliResult.stderr).toBe(0);
    const inventory = inventoryFrom(cliResult.json);
    const digest = createHash("sha256").update(bytes).digest("hex");
    expect(inventory.ines).toMatchObject({
      header: {
        mapper: 19,
        trainer_present: true,
        prg_rom_units_16k: 2,
        chr_rom_units_8k: 1,
      },
      reconstruction: { bytes: bytes.length, sha256: digest, verified: true },
    });
    const expected = [
      ["header.bin", 0, 16],
      ["trainer.bin", 16, 512],
      ["prg/000.bin", 528, 16_384],
      ["prg/001.bin", 16_912, 16_384],
      ["chr/000.bin", 33_296, 8_192],
      ["trailing.bin", 41_488, 4],
    ] as const;
    const nodes = new Map(
      inventory.nodes.map((node) => [node.artifact_id, node]),
    );
    for (const [logical_path, offset, length] of expected) {
      const occurrence = inventory.occurrences.find(
        (item) => item.logical_path === logical_path,
      );
      if (
        occurrence?.artifact_id === undefined ||
        occurrence.artifact_id === null
      )
        throw new Error(`Missing region ${logical_path}`);
      expect(occurrence.source_location).toEqual({ offset, length });
      expect(nodes.get(occurrence.artifact_id)?.sha256).toBe(
        createHash("sha256")
          .update(bytes.subarray(offset, offset + length))
          .digest("hex"),
      );
    }

    const { call } = await connectLocalToolsMcp();
    const opened = await call("open_binary", { path });
    if (opened.isError)
      throw new Error(JSON.stringify(parseMcpToolError(opened)));
    const inspected = await call("inspect_artifact", {});
    expect(
      inspected.isError,
      JSON.stringify(inspected.structuredContent),
    ).not.toBe(true);
    expect(inventoryFrom(inspected.structuredContent)).toEqual(inventory);
    const extracted = await call("extract_artifact", {});
    expect(
      extracted.isError,
      JSON.stringify(extracted.structuredContent),
    ).not.toBe(true);
    const extraction = artifactExtractionResultSchema.parse(
      parseEvidence(extracted.structuredContent).normalized_result,
    );
    try {
      expect(extraction.artifacts).toHaveLength(expected.length);
      expect(
        Buffer.concat(
          await Promise.all(
            expected.map(([region]) =>
              readFile(join(extraction.output_root, region)),
            ),
          ),
        ),
      ).toEqual(bytes);
    } finally {
      // The successful extraction transfers this exact output directory to the caller.
      await rm(extraction.output_root, { recursive: true, force: true });
    }
    await call("close_binary", {});
    expect(await readFile(path)).toEqual(bytes);
  },
);

cliTest(
  "unsupported NES containers fail explicitly and leave a valid MCP session usable",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-ines-public-refusal-");
    const validPath = join(root, "valid.nes");
    await writeFile(validPath, inesFixture({ chrUnits: 0 }));
    const { call } = await connectLocalToolsMcp();
    const opened = await call("open_binary", { path: validPath });
    if (opened.isError)
      throw new Error(JSON.stringify(parseMcpToolError(opened)));
    for (const [name, bytes, reason] of [
      ["truncated", inesFixture().subarray(0, 20), "truncated iNES payload"],
      [
        "nes2",
        (() => {
          const bytes = inesFixture();
          bytes[7] = 8;
          return bytes;
        })(),
        "nes-2.0",
      ],
      ["unif", Buffer.from("UNIF"), "unif"],
    ] as const) {
      const path = join(root, `${name}.nes`);
      await writeFile(path, bytes);
      const refused = await cli.run({
        arguments: ["inspect-artifact", path, "--json"],
      });
      expect(refused.exitCode).not.toBe(0);
      expect(JSON.stringify(refused.json)).toContain(reason);
      const switched = await call("open_binary", { path });
      expect(switched.isError).toBe(true);
      expect(JSON.stringify(parseMcpToolError(switched))).toContain(reason);
    }
    const retained = await call("inspect_artifact", {});
    expect(
      retained.isError,
      JSON.stringify(retained.structuredContent),
    ).not.toBe(true);
    const inventory = inventoryFrom(retained.structuredContent);
    expect(inventory.ines?.header.chr_rom_units_8k).toBe(0);
    expect(
      inventory.occurrences.some(({ logical_path }) =>
        logical_path.startsWith("chr/"),
      ),
    ).toBe(false);
    await call("close_binary", {});
  },
);
