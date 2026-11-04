// @effect-diagnostics nodeBuiltinImport:off -- the test writes a temporary policy file.
/**
 * Tailor fork (TailorAU/t3code): worktree checks with the machine policy actually installed.
 * The ProgramData known folder is pointed at a temp folder holding a test t3-policy.json
 * (machinePolicy.setProgramDataFolderForTests), so the same code paths run as on a real
 * install: Orchestrator.dispatch (thread.create, thread.metadata.update) and the MCP project
 * toolkit's existing-worktree check.
 */
import * as NodeFS from "node:fs";
import * as NodeOS from "node:os";
import * as NodePath from "node:path";
import { afterAll, assert, beforeAll, describe, it } from "@effect/vitest";
import {
  CommandId,
  EventId,
  ProjectId,
  ProviderDriverKind,
  ProviderInstanceId,
  ThreadId,
} from "@t3tools/contracts";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";

import * as SqlitePersistence from "../persistence/Sqlite.ts";
import { CodexProviderCapabilitiesV2 } from "../orchestration-v2/Adapters/CodexAdapterV2.ts";
import * as Orchestrator from "../orchestration-v2/Orchestrator.ts";
import * as ProjectStore from "../orchestration-v2/ProjectStore.ts";
import * as ProjectionStore from "../orchestration-v2/ProjectionStore.ts";
import * as ProviderAdapterRegistry from "../orchestration-v2/ProviderAdapterRegistry.ts";
import * as ProviderReplayHarness from "../orchestration-v2/testkit/ProviderReplayHarness.ts";
import type * as ProviderAdapter from "@t3tools/provider-core/server/ProviderAdapter";
import * as TailorMachinePolicy from "./machinePolicy.ts";

const base = NodeFS.mkdtempSync(NodePath.join(NodeOS.tmpdir(), "t3-policy-installed-"));
const programData = NodePath.join(base, "ProgramData");
const workspaces = NodePath.join(base, "workspaces");
const projectRoot = NodePath.join(workspaces, "app");
const outside = NodePath.join(base, "outside");

beforeAll(() => {
  NodeFS.mkdirSync(NodePath.join(programData, "T3CodePolicy"), { recursive: true });
  NodeFS.mkdirSync(NodePath.join(projectRoot, "wt"), { recursive: true });
  NodeFS.mkdirSync(outside, { recursive: true });
  NodeFS.writeFileSync(
    NodePath.join(programData, "T3CodePolicy", "t3-policy.json"),
    JSON.stringify({
      installed: {
        claudeConfigDir: NodePath.join(programData, "T3CodePolicy", "claude-home"),
        claudeExe: "C:\\Program Files\\T3Code\\claude\\claude.exe",
        workspaceRoots: [workspaces],
        gitExe: "C:\\Program Files\\Git\\cmd\\git.exe",
      },
    }),
  );
  TailorMachinePolicy.setProgramDataFolderForTests(programData);
});
afterAll(() => {
  TailorMachinePolicy.setProgramDataFolderForTests(undefined);
});

const instanceId = ProviderInstanceId.make("codex");
const adapter = {
  instanceId,
  driver: ProviderDriverKind.make("codex"),
  getCapabilities: () => Effect.succeed(CodexProviderCapabilitiesV2),
  planSelectionTransition: () => Effect.succeed({ type: "apply_on_next_turn" as const }),
  openSession: () => Effect.die("No provider process needed for these commands"),
} as ProviderAdapter.ProviderAdapterV2["Service"];
const layerDatabase = SqlitePersistence.layerMemory;
const layerOrchestrator = Layer.mergeAll(
  layerDatabase,
  ProjectionStore.layer.pipe(Layer.provide(layerDatabase)),
  ProjectStore.layer.pipe(Layer.provide(layerDatabase)),
  ProviderReplayHarness.layerWithRegistry(
    { name: "tailor-worktree-policy" },
    ProviderAdapterRegistry.layerFromAdapters([adapter]),
    { databaseLayer: layerDatabase, runEffectWorker: false },
  ),
);

const projectId = ProjectId.make("project:tailor-policy");
const createProject = Effect.gen(function* () {
  const projects = yield* ProjectStore.ProjectStoreV2;
  yield* projects.apply({
    sequence: 1,
    eventId: EventId.make("event:tailor-policy-project"),
    aggregateKind: "project",
    aggregateId: projectId,
    occurredAt: "2026-11-05T00:00:00.000Z",
    commandId: null,
    causationEventId: null,
    correlationId: null,
    metadata: {},
    type: "project.created",
    payload: {
      projectId,
      title: "Policy project",
      workspaceRoot: projectRoot,
      defaultModelSelection: { instanceId, model: "gpt-5" },
      scripts: [],
      createdAt: "2026-11-05T00:00:00.000Z",
      updatedAt: "2026-11-05T00:00:00.000Z",
    },
  });
});

const createThread = (threadId: ThreadId, worktreePath: string | null) =>
  Effect.gen(function* () {
    const orchestrator = yield* Orchestrator.OrchestratorV2;
    return yield* orchestrator.dispatch({
      type: "thread.create",
      commandId: CommandId.make(`create:${threadId}`),
      threadId,
      projectId,
      title: "Thread",
      modelSelection: { instanceId, model: "gpt-5" },
      runtimeMode: "approval-required",
      interactionMode: "default",
      branch: null,
      worktreePath,
      createdBy: "user",
      creationSource: "web",
    });
  });

describe.skipIf(process.platform !== "win32")("with the machine policy installed", () => {
  it("the policy is read from the stubbed known folder", () => {
    const state = TailorMachinePolicy.readTailorPolicy("win32");
    assert.strictEqual(state._tag, "installed");
  });

  it.layer(layerOrchestrator)("Orchestrator.dispatch", (it) => {
    it.effect("refuses a thread worktree outside the project, and allows one inside", () =>
      Effect.gen(function* () {
        yield* createProject;
        const refused = yield* Effect.flip(createThread(ThreadId.make("thread:outside"), outside));
        assert.strictEqual(refused._tag, "OrchestratorCommandRejectedError");
        const inPolicyFolder = yield* Effect.flip(
          createThread(
            ThreadId.make("thread:policy"),
            NodePath.join(programData, "T3CodePolicy", "connector"),
          ),
        );
        assert.strictEqual(inPolicyFolder._tag, "OrchestratorCommandRejectedError");
        yield* createThread(ThreadId.make("thread:inside"), NodePath.join(projectRoot, "wt"));
        yield* createThread(ThreadId.make("thread:none"), null);
      }),
    );

    it.effect("refuses thread.metadata.update to a worktree outside the project", () =>
      Effect.gen(function* () {
        yield* createProject;
        const threadId = ThreadId.make("thread:metadata");
        yield* createThread(threadId, null);
        const orchestrator = yield* Orchestrator.OrchestratorV2;
        const refused = yield* Effect.flip(
          orchestrator.dispatch({
            type: "thread.metadata.update",
            commandId: CommandId.make("metadata:outside"),
            threadId,
            worktreePath: outside,
          }),
        );
        assert.strictEqual(refused._tag, "OrchestratorCommandRejectedError");
        yield* orchestrator.dispatch({
          type: "thread.metadata.update",
          commandId: CommandId.make("metadata:inside"),
          threadId,
          worktreePath: NodePath.join(projectRoot, "wt"),
        });
      }),
    );
  });

  it("the MCP and server path rules come from the installed policy", () => {
    const rules = TailorMachinePolicy.tailorPathRulesIfInstalled("win32", NodePath.join(base, "t3-home", "worktrees"));
    assert.isDefined(rules);
    assert.deepEqual(rules?.workspaceRoots, [workspaces]);
  });
});
