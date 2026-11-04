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
import { RPC_REQUIRED_SCOPES, requiredScopeForRpcMethod } from "../auth/RpcAuthorization.ts";

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
});
