import {
  AcpRegistryDriver,
  type AcpRegistryDriverEnv,
} from "@t3tools/provider-acp-registry/server";
import { AntigravityDriver, type AntigravityDriverEnv } from "./Drivers/AntigravityDriver.ts";
import { ClaudeDriver, type ClaudeDriverEnv } from "./Drivers/ClaudeDriver.ts";
import { CodexDriver, type CodexDriverEnv } from "./Drivers/CodexDriver.ts";
import { CursorDriver, type CursorDriverEnv } from "@t3tools/provider-cursor/server";
import { FxDriver, type FxDriverEnv } from "@t3tools/provider-fx/server";
import { GrokDriver, type GrokDriverEnv } from "@t3tools/provider-grok/server";
import { OpenCodeDriver, type OpenCodeDriverEnv } from "@t3tools/provider-opencode/server";
import { MuseDriver, type MuseDriverEnv } from "@t3tools/provider-muse/server";
import { PiDriver, type PiDriverEnv } from "@t3tools/provider-pi/server";
import type {
  AnyProviderDriver,
  ProviderUsageReaderEnv,
} from "@t3tools/provider-core/server/driver";

export type BuiltInDriversEnv =
  | AcpRegistryDriverEnv
  | AntigravityDriverEnv
  | ClaudeDriverEnv
  | CodexDriverEnv
  | CursorDriverEnv
  | FxDriverEnv
  | GrokDriverEnv
  | OpenCodeDriverEnv
  | PiDriverEnv
  | MuseDriverEnv;

/**
 * Tailor fork (TailorAU/t3code): the Cursor driver is off at compile time. `@cursor/sdk`
 * bundles its own copy of the MCP SDK inside its Webpack chunks, which the workspace
 * `@modelcontextprotocol/sdk` override cannot patch. Flip this only in a reviewed PR that
 * re-checks the bundled copy (tailor/SECURITY-REVIEW.md, finding T3-04).
 */
export const TAILOR_CURSOR_DRIVER_ENABLED = false as boolean;

const withoutDisabledDrivers = <D>(drivers: ReadonlyArray<D>): ReadonlyArray<D> =>
  TAILOR_CURSOR_DRIVER_ENABLED
    ? drivers
    : drivers.filter((driver) => (driver as unknown) !== CursorDriver);

export const BUILT_IN_DRIVERS: ReadonlyArray<AnyProviderDriver<BuiltInDriversEnv>> =
  withoutDisabledDrivers<AnyProviderDriver<BuiltInDriversEnv>>([
    CodexDriver,
    ClaudeDriver,
    CursorDriver,
    GrokDriver,
    FxDriver,
    OpenCodeDriver,
    AntigravityDriver,
    PiDriver,
    MuseDriver,
    AcpRegistryDriver,
  ]);

export type BuiltInUsageReadersEnv =
  | ProviderUsageReaderEnv<typeof ClaudeDriver>
  | ProviderUsageReaderEnv<typeof CodexDriver>
  | ProviderUsageReaderEnv<typeof GrokDriver>
  | ProviderUsageReaderEnv<typeof OpenCodeDriver>
  | ProviderUsageReaderEnv<typeof AntigravityDriver>
  | ProviderUsageReaderEnv<typeof CursorDriver>
  | ProviderUsageReaderEnv<typeof PiDriver>
  | ProviderUsageReaderEnv<typeof MuseDriver>;

/** Order matters: aggregation keeps the first duplicate record. */
export const BUILT_IN_USAGE_DRIVERS: ReadonlyArray<
  AnyProviderDriver<BuiltInDriversEnv, BuiltInUsageReadersEnv>
> = withoutDisabledDrivers<AnyProviderDriver<BuiltInDriversEnv, BuiltInUsageReadersEnv>>([
  ClaudeDriver,
  CodexDriver,
  GrokDriver,
  PiDriver,
  OpenCodeDriver,
  MuseDriver,
  AntigravityDriver,
  CursorDriver,
]);
