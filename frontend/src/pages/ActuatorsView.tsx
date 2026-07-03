import {
  useGetActuatorsStatusQuery,
  useGetActuatorsAuditQuery,
  useActuatorControlMutation,
  useGetAutonomyQuery,
  useGetCandidatesQuery,
} from "../api";
import { ActuatorState, AuditEntry } from "../types";

function AutonomyPanel() {
  const { data: auto } = useGetAutonomyQuery(undefined, { pollingInterval: 3000 });
  const { data: candidates = [] } = useGetCandidatesQuery(undefined, { pollingInterval: 5000 });
  const [control, { isLoading }] = useActuatorControlMutation();

  const reachable = auto && auto.reachable !== false;
  const armed = !!auto?.auto_armed;
  const runnable = candidates.filter((c) => c.runnable).length;

  return (
    <div className="rounded-lg border-2 border-subtle bg-panel p-4 mb-6">
      <div className="flex items-center justify-between mb-2">
        <h2 className="font-bold text-lg">Autonomy</h2>
        {reachable && auto?.tripped && (
          <span className="text-xs px-2 py-0.5 rounded bg-red-500/25 text-red-600 dark:text-red-400 font-semibold">
            BREAKER TRIPPED
          </span>
        )}
      </div>
      <p className="text-xs text-secondary mb-3">
        When armed, the loop auto-detects exploit clusters (scoreboard + flag-out),
        proves them at NOP, and fans out to real teams — each exploit at each team
        at most once per tick, rate- and budget-capped. Requires the replicator
        armed too.
      </p>
      <div className="flex items-center gap-4 flex-wrap">
        <span
          className={`text-sm px-2 py-1 rounded ${
            armed
              ? "bg-red-500/25 text-red-600 dark:text-red-400 font-semibold"
              : "bg-green-500/20 text-green-600 dark:text-green-400"
          }`}
        >
          auto {armed ? "ARMED" : "off"}
        </span>
        <span className="text-xs text-secondary">
          replicator {auto?.replicator_armed ? "armed" : "disarmed"} · tick {auto?.tick ?? "—"} ·{" "}
          {auto?.proven?.length ?? 0} proven · {runnable}/{candidates.length} candidates runnable
        </span>
        <div className="ml-auto flex gap-2">
          <button
            className="btn-primary text-xs disabled:opacity-40"
            disabled={!reachable || armed || isLoading}
            onClick={() => control({ which: "replicator", action: "auto_arm" })}
          >
            Arm autonomy
          </button>
          <button
            className="px-3 py-1 rounded text-xs bg-red-600 text-white font-semibold disabled:opacity-40"
            disabled={!reachable || isLoading}
            onClick={() => control({ which: "replicator", action: "auto_disarm" })}
          >
            KILL
          </button>
        </div>
      </div>
    </div>
  );
}

function ActuatorCard({
  title,
  which,
  state,
  capability,
}: {
  title: string;
  which: string;
  state: ActuatorState | undefined;
  capability: string;
}) {
  const [control, { isLoading }] = useActuatorControlMutation();
  const reachable = state && state.reachable !== false;
  const armed = !!state?.armed;

  return (
    <div className="rounded-lg border border-subtle bg-panel p-4 w-72">
      <div className="flex items-center justify-between mb-1">
        <h2 className="font-bold">{title}</h2>
        {!reachable ? (
          <span className="text-xs text-secondary">unreachable</span>
        ) : (
          <span
            className={`text-xs px-2 py-0.5 rounded ${
              armed
                ? "bg-red-500/25 text-red-600 dark:text-red-400 font-semibold"
                : "bg-green-500/20 text-green-600 dark:text-green-400"
            }`}
          >
            {armed ? "ARMED" : "disarmed"}
          </span>
        )}
      </div>
      <p className="text-xs text-secondary mb-3">{capability}</p>
      <div className="flex gap-2">
        <button
          className="btn-primary text-xs disabled:opacity-40"
          disabled={!reachable || armed || isLoading}
          onClick={() => control({ which, action: "arm" })}
        >
          Arm
        </button>
        <button
          className="btn-primary text-xs disabled:opacity-40"
          disabled={!reachable || !armed || isLoading}
          onClick={() => control({ which, action: "disarm" })}
        >
          Disarm
        </button>
      </div>
      {state?.proven && state.proven.length > 0 && (
        <p className="text-xs text-secondary mt-2">
          NOP-proven: {state.proven.length}
        </p>
      )}
    </div>
  );
}

function AuditList({ title, entries }: { title: string; entries: AuditEntry[] | { error?: string } }) {
  const rows = Array.isArray(entries) ? entries : [];
  return (
    <div className="flex-1 min-w-0">
      <h3 className="font-semibold mb-2">{title}</h3>
      {rows.length === 0 ? (
        <p className="text-xs text-secondary">No actions recorded.</p>
      ) : (
        <table className="w-full text-xs border-collapse">
          <tbody>
            {rows
              .slice()
              .reverse()
              .map((e, i) => (
                <tr key={i} className="border-b border-subtle">
                  <td className="px-2 py-1 font-mono">{e.action}</td>
                  <td className="px-2 py-1 font-mono text-secondary truncate max-w-[16rem]">
                    {e.subject}
                  </td>
                  <td className="px-2 py-1">
                    <span
                      className={
                        e.decision?.allow
                          ? "text-green-600 dark:text-green-400"
                          : "text-red-600 dark:text-red-400"
                      }
                    >
                      {e.decision?.reason}
                    </span>
                  </td>
                </tr>
              ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export function ActuatorsView() {
  const { data: status } = useGetActuatorsStatusQuery(undefined, { pollingInterval: 4000 });
  const { data: audit } = useGetActuatorsAuditQuery(undefined, { pollingInterval: 4000 });

  return (
    <div className="flex flex-col h-full p-4 bg-main text-app overflow-auto">
      <h1 className="text-2xl font-bold mb-1">Actuators</h1>
      <p className="text-sm text-secondary mb-4">
        Offense and defense both start <b>disarmed</b>. Arming is a deliberate act;
        every fire path stays gated (anti-leak allowlist, NOP-proven before
        fan-out, SLA-safe patches) even once armed.
      </p>
      <AutonomyPanel />
      <div className="flex flex-wrap gap-4 mb-6">
        <ActuatorCard
          title="Replicator"
          which="replicator"
          state={status?.replicator}
          capability="Replays exploits at opponents, submits flags to the farm."
        />
        <ActuatorCard
          title="Patch engine"
          which="patch"
          state={status?.patch_engine}
          capability="Deploys firegex rules that drop attack traffic."
        />
      </div>
      <div className="flex flex-wrap gap-8">
        <AuditList title="Replicator audit" entries={audit?.replicator ?? []} />
        <AuditList title="Patch-engine audit" entries={audit?.patch_engine ?? []} />
      </div>
    </div>
  );
}
