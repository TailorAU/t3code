/**
 * Tailor fork (TailorAU/t3code): the connector's token carries only
 * `orchestration:read` and `orchestration:operate`
 * (`t3 auth session issue --scope orchestration:read --scope orchestration:operate`).
 * This pins the server-side scope of every RPC the connector calls, and proves that
 * scope set reaches no terminal, access-management, relay, settings or self-update RPC.
 */
import {
  AuthOrchestrationOperateScope,
  AuthOrchestrationReadScope,
  WS_METHODS,
  type AuthEnvironmentScope,
} from "@t3tools/contracts";
import { describe, expect, it } from "@effect/vitest";

import contract from "../../../../tailor/contract/connector-rpc-contract.json" with { type: "json" };
import {
  RPC_REQUIRED_SCOPES,
  requiredScopeForRpcMethod,
  tailorConnectorAllows,
} from "../auth/RpcAuthorization.ts";
import { TAILOR_CONNECTOR_COMMANDS, TAILOR_CONNECTOR_RPCS } from "@t3tools/contracts";

const CONNECTOR_SCOPES: ReadonlyArray<AuthEnvironmentScope> = [
  AuthOrchestrationReadScope,
  AuthOrchestrationOperateScope,
];

const rpcs = contract.rpcs as unknown as Readonly<
  Record<string, { readonly requiredScope: string }>
>;

describe("Tailor connector token scopes", () => {
  it("pins the scope of each RPC the connector calls", () => {
    for (const [method, rpc] of Object.entries(rpcs)) {
      expect(requiredScopeForRpcMethod(method), method).toBe(rpc.requiredScope);
      expect(CONNECTOR_SCOPES, method).toContain(rpc.requiredScope);
    }
  });

  it("keeps terminal, access, relay, settings and update RPCs out of the connector's reach", () => {
    const outOfReach = [
      WS_METHODS.terminalOpen,
      WS_METHODS.terminalAttach,
      WS_METHODS.terminalWrite,
      WS_METHODS.terminalObserve,
      WS_METHODS.guestShareCreate,
      WS_METHODS.peerLinksLink,
      WS_METHODS.peerLinksAnswerRequest,
      WS_METHODS.subscribeAuthAccess,
      WS_METHODS.serverUpdateServer,
      WS_METHODS.cloudInstallRelayClient,
    ];
    for (const method of outOfReach) {
      expect(CONNECTOR_SCOPES, method).not.toContain(requiredScopeForRpcMethod(method));
    }
    // Every terminal RPC needs a terminal scope.
    for (const method of Object.keys(RPC_REQUIRED_SCOPES)) {
      if (!method.startsWith("terminal.")) continue;
      expect(CONNECTOR_SCOPES, method).not.toContain(requiredScopeForRpcMethod(method));
    }
  });

  it("gives the tailor:connector scope exactly the contract RPCs and commands", () => {
    const contractRpcs = Object.keys(rpcs).sort();
    expect([...TAILOR_CONNECTOR_RPCS].sort()).toEqual(contractRpcs);
    const commands = (
      contract.rpcs as unknown as Record<string, { readonly commands?: Record<string, unknown> }>
    )["orchestration.dispatchCommand"]?.commands;
    expect([...TAILOR_CONNECTOR_COMMANDS].sort()).toEqual(Object.keys(commands ?? {}).sort());

    for (const method of TAILOR_CONNECTOR_RPCS) {
      if (method === "orchestration.dispatchCommand") continue;
      expect(tailorConnectorAllows(method, {}), method).toBe(true);
    }
    for (const type of TAILOR_CONNECTOR_COMMANDS) {
      expect(tailorConnectorAllows("orchestration.dispatchCommand", { type }), type).toBe(true);
    }
    // Every other dispatch command and every other RPC is refused.
    for (const type of ["thread.runtime-mode.set", "thread.delete", "checkpoint.rollback", "thread.fork"]) {
      expect(tailorConnectorAllows("orchestration.dispatchCommand", { type }), type).toBe(false);
    }
    expect(tailorConnectorAllows("orchestration.dispatchCommand", undefined)).toBe(false);
    for (const method of Object.keys(RPC_REQUIRED_SCOPES)) {
      if ((TAILOR_CONNECTOR_RPCS as ReadonlyArray<string>).includes(method)) continue;
      expect(tailorConnectorAllows(method, {}), method).toBe(false);
    }
  });
});
