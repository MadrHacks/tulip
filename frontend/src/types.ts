export interface Flow {
  id: Id;
  src_port: number;
  dst_port: number;
  src_ip: string;
  dst_ip: string;
  time: number;
  duration: number;
  // TODO: Get this from backend instead of hacky workaround
  service_tag: string;
  num_packets: number;
  parent_id: Id;
  child_id: Id;
  tags: string[];
  flags: string[];
  flagids: string[];
  suricata: number[];
  filename: string;
  fuzzyhash: string;
  similarity: number;
}

export interface TickInfo {
  startDate: string;
  tickLength: number;
  flagLifetime: number;
}

export interface FullFlow extends Flow {
  signatures: Signature[];
  flow: FlowRepresentation[];
}

export type Id = string;

export interface FlowRepresentation {
  type: string;
  flow: FlowData[];
}

export interface FlowData {
  from: string;
  data: string;
  b64: string;
  time: number;
}

export interface Signature {
  id: number;
  message: string;
  action: string;
}

// TODO: pagination WTF
export interface FlowsQuery {
  // Text filter
  regex_insensitive?: string;
  // Service filter
  // TODO: Why not use service name here?
  service?: string;
  ip_dst?: string;
  port_dst?: number;
  time_from?: string;
  time_to?: string;
  tags_include?: string[];
  tags_exclude?: string[];
  tag_intersection_mode?: "AND" | "OR";
  flags?: string[];
  flagids?: string[];
  similarity?: string;
  fuzzyhash_include?: string[];
  fuzzyhash_exclude?: string[];
}

export interface StatsQuery {
  service: string;
  tick_from: number;
  tick_to: number;
}

export interface Stats {
  [key: string]: number; // little hack to make typescript happy
  tick: number;
  tag_flag_in: number;
  tag_flag_out: number;
  tag_blocked: number;
  tag_suricata: number;
  tag_enemy: number;
  flag_in: number;
  flag_out: number;
};

export type Service = {
  ip: string;
  port: number;
  name: string;
};

export type TicksAttackInfo = Record<number, Record<string, number>>;

export interface TicksAttackQuery {
  from_tick: number;
  to_tick: number;
}

// A Shape is a NEUTRAL recurring request pattern mined from flows. Every field
// is an observed SIGNAL, never a verdict: flag_present counts members whose
// response leaked a flag (a candidate-exfil signal — the checker leaks flags
// too, so this is not proof of an attack), flag_in counts members that stored a
// flag. "Exploit" status is earned later (nop-proof / human), not asserted here.
export interface Shape {
  tag: string;
  service: string;
  shape_id: number;
  template: string;
  members: number;
  flag_present: number;
  flag_in: number;
  actors: Record<string, number>;
  size: number;
  first_seen: number;
  last_seen: number;
}

export interface ClusterTemplate {
  service: string;
  cluster_id: number;
  tag: string;
  slots: string[];
  version: number;
}

export interface Chain {
  id: number;
  tag: string;
  signature: string;
  count: number;
  steps: string[];
  links: number;
  runnable: boolean;
}

export interface Heat {
  our_lost: number;
  our_stolen: number;
  total_stolen: number;
  our_sla_ok: boolean;
}

export interface ActuatorState {
  armed?: boolean;
  proven?: string[];
  reachable?: boolean;
  error?: string;
}

export interface ActuatorsStatus {
  replicator: ActuatorState;
  patch_engine: ActuatorState;
}

export interface AuditEntry {
  capability?: string;
  action?: string;
  level?: string;
  subject?: string;
  decision?: { allow?: boolean; reason?: string };
}

export interface ActuatorsAudit {
  replicator: AuditEntry[] | { error?: string };
  patch_engine: AuditEntry[] | { error?: string };
}

export interface Autonomy {
  auto_armed?: boolean;
  replicator_armed?: boolean;
  tripped?: boolean;
  tick?: number;
  proven?: string[];
  reachable?: boolean;
  error?: string;
}

export interface AttackCandidate {
  service: string;
  cluster_id: number;
  tag: string;
  flag_out: number;
  n: number;
  port: number;
  runnable: boolean;
}

export interface ChainPlanStep {
  service: string;
  port: number;
  template: { slots?: { type: string }[] };
}

export interface ChainPlanLink {
  producer_step: number;
  consumer_step: number;
  extract: string;
  inject_slot: number;
}

export interface ChainPlan {
  steps: ChainPlanStep[];
  links: ChainPlanLink[];
}

export interface ChainBody {
  pattern: {
    steps: { cluster_id: string }[];
    links: { producer_step: number; consumer_step: number }[];
  };
  plan: ChainPlan | null;
}
