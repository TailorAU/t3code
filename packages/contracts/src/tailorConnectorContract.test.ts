/**
 * Tailor fork (TailorAU/t3code): contract test for the WebSocket RPCs the Tailor
 * connector calls. The fixture in tailor/contract/connector-rpc-contract.json is the
 * reviewed surface at the pinned version. Any upstream bump that renames a method,
 * changes its stream mode, or adds, removes or re-optionalises a field the connector
 * sends must fail here, so the bump PR updates the connector adapter on purpose.
 */
import { describe, expect, it } from "vite-plus/test";
import * as Exit from "effect/Exit";
import * as Schema from "effect/Schema";
import * as SchemaAST from "effect/SchemaAST";
import { RpcSchema } from "effect/rpc";

import contract from "../../../tailor/contract/connector-rpc-contract.json" with { type: "json" };
import {
  ORCHESTRATION_V2_WS_METHODS,
  OrchestrationV2Actor,
  OrchestrationV2Command,
  OrchestrationV2CreationSource,
  OrchestrationV2PendingRuntimeRequestSummary,
  OrchestrationV2RpcSchemas,
  OrchestrationV2ShellSnapshot,
  OrchestrationV2ShellStreamItem,
  OrchestrationV2ThreadShell,
} from "./orchestrationV2.ts";
import { ProviderApprovalDecision, RuntimeMode } from "./providerPolicy.ts";
import { WsRpcGroup } from "./rpc.ts";

type RpcContract = {
  readonly schemaKey: keyof typeof OrchestrationV2RpcSchemas;
  readonly stream: boolean;
  readonly requiredScope: string;
  readonly input?: ReadonlyArray<string>;
  readonly output?: ReadonlyArray<string>;
  readonly commands?: Readonly<Record<string, ReadonlyArray<string>>>;
};

const rpcs = contract.rpcs as unknown as Readonly<Record<string, RpcContract>>;

/** Field names of a struct schema, sorted, with `?` on optional ones. */
function shape(schema: Schema.Top): ReadonlyArray<string> {
  const ast = schema.ast;
  if (!SchemaAST.isObjects(ast)) {
    throw new Error("expected a struct schema");
  }
  return ast.propertySignatures
    .map((property) => {
      const optional = (property.type.context as { readonly isOptional?: boolean } | undefined)
        ?.isOptional;
      return `${String(property.name)}${optional === true ? "?" : ""}`;
    })
    .sort();
}

function literalsOf(schema: unknown): ReadonlyArray<unknown> {
  const value = schema as { readonly literals?: ReadonlyArray<unknown>; readonly literal?: unknown };
  return value.literals ?? (value.literal === undefined ? [] : [value.literal]);
}

function discriminated(
  union: { readonly members: ReadonlyArray<Schema.Top> },
  key: string,
  value: string,
): Schema.Top {
  const matches = union.members.filter((member) => {
    const fields = (member as unknown as { readonly fields?: Record<string, unknown> }).fields;
    return fields !== undefined && literalsOf(fields[key]).includes(value);
  });
  if (matches.length !== 1) {
    throw new Error(`expected exactly one ${key}=${value} member, found ${matches.length}`);
  }
  return matches[0]!;
}

function memberLiterals(
  union: { readonly members: ReadonlyArray<Schema.Top> },
  key: string,
): ReadonlyArray<unknown> {
  return union.members.flatMap((member) => {
    const fields = (member as unknown as { readonly fields?: Record<string, unknown> }).fields;
    return fields === undefined ? [] : literalsOf(fields[key]);
  });
}

const sorted = (values: ReadonlyArray<string>) => [...values].sort();

describe("Tailor connector RPC contract", () => {
  it("pins every connector method name and its schema key", () => {
    const methods = ORCHESTRATION_V2_WS_METHODS as Readonly<Record<string, string>>;
    for (const [method, rpc] of Object.entries(rpcs)) {
      expect(methods[rpc.schemaKey], method).toBe(method);
      expect(WsRpcGroup.requests.has(method), `${method} is registered`).toBe(true);
    }
  });

  it("keeps each method's stream mode", () => {
    for (const [method, rpc] of Object.entries(rpcs)) {
      const registered = WsRpcGroup.requests.get(method);
      if (registered === undefined) throw new Error(`${method} is not registered`);
      const isStream = RpcSchema.isStreamSchema(registered.successSchema);
      expect(isStream, `${method} stream mode`).toBe(rpc.stream);
    }
  });

  it("keeps the input and output fields the connector sends and reads", () => {
    for (const [method, rpc] of Object.entries(rpcs)) {
      const schemas = OrchestrationV2RpcSchemas[rpc.schemaKey] as {
        readonly input: Schema.Top;
        readonly output: Schema.Top;
      };
      if (rpc.input !== undefined) {
        expect(shape(schemas.input), `${method} input`).toEqual(sorted(rpc.input));
      }
      if (rpc.output !== undefined) {
        expect(shape(schemas.output), `${method} output`).toEqual(sorted(rpc.output));
      }
    }
  });

  it("keeps the dispatch commands the connector sends", () => {
    const commands = rpcs["orchestration.dispatchCommand"]?.commands ?? {};
    expect(Object.keys(commands).length).toBeGreaterThan(0);
    for (const [type, fields] of Object.entries(commands)) {
      expect(shape(discriminated(OrchestrationV2Command, "type", type)), type).toEqual(
        sorted(fields),
      );
    }
  });

  it("decodes the connector's minimal interrupt and respond commands", () => {
    const dispatch = WsRpcGroup.requests.get(ORCHESTRATION_V2_WS_METHODS.dispatchCommand);
    if (dispatch === undefined) throw new Error("dispatchCommand is not registered");
    const decode = Schema.decodeUnknownExit(dispatch.payloadSchema);
    const base = { commandId: "tailor-contract-1", threadId: "thread-1" };
    expect(Exit.isSuccess(decode({ ...base, type: "run.interrupt", runId: "run-1" }))).toBe(true);
    expect(
      Exit.isSuccess(
        decode({
          ...base,
          type: "runtime-request.respond",
          requestId: "request-1",
          decision: "decline",
        }),
      ),
    ).toBe(true);
    // A respond without its request id must not decode.
    expect(Exit.isFailure(decode({ ...base, type: "runtime-request.respond" }))).toBe(true);
  });

  it("keeps the literal sets the connector maps", () => {
    expect(literalsOf(RuntimeMode)).toEqual(contract.literals.RuntimeMode);
    expect(literalsOf(ProviderApprovalDecision)).toEqual(contract.literals.ProviderApprovalDecision);
    expect(literalsOf(OrchestrationV2CreationSource)).toEqual(
      contract.literals.OrchestrationV2CreationSource,
    );
    expect(literalsOf(OrchestrationV2Actor)).toEqual(contract.literals.OrchestrationV2Actor);
    expect(memberLiterals(OrchestrationV2ShellStreamItem, "kind")).toEqual(
      contract.literals.ShellStreamItemKinds,
    );
  });

  it("still carries the snapshot fields the connector reads", () => {
    const reads: ReadonlyArray<readonly [string, Schema.Top]> = [
      ["OrchestrationV2ShellSnapshot", OrchestrationV2ShellSnapshot],
      ["OrchestrationV2ThreadShell", OrchestrationV2ThreadShell],
      ["OrchestrationV2PendingRuntimeRequestSummary", OrchestrationV2PendingRuntimeRequestSummary],
    ];
    const expected = contract.reads as Readonly<Record<string, ReadonlyArray<string>>>;
    for (const [name, schema] of reads) {
      const actual = shape(schema);
      for (const field of expected[name] ?? []) {
        expect(actual, `${name}.${field}`).toContain(field);
      }
    }
  });
});
