#!/usr/bin/env python3
import sys, json, csv, os, argparse

def main():
    ap = argparse.ArgumentParser(description="Convert agent NDJSON logs to CSVs")
    ap.add_argument("ndjson", help="Path to .ndjson produced by --log-json")
    ap.add_argument("--out-dir", help="Output directory (default: same as input)")
    args = ap.parse_args()

    in_path = args.ndjson
    out_dir = args.out_dir or os.path.dirname(os.path.abspath(in_path)) or "."

    ticks_csv = os.path.join(out_dir, "ticks.csv")
    actions_csv = os.path.join(out_dir, "actions.csv")

    with open(in_path, "r") as f,          open(ticks_csv, "w", newline="") as ft,          open(actions_csv, "w", newline="") as fa:
        tw = csv.writer(ft)
        aw = csv.writer(fa)
        tw.writerow(["ts_ms","pid","strategy","dry_run","threads","runq_us","futex_us","page_faults_sum","psi_cpu_some","psi_mem_some","comm_wake","comm_futex","llc_per_thread","total_cpus","spikes","io_dev","io_seq_ratio","num_actions"])
        aw.writerow(["ts_ms","pid","action_type","pid_field","cgroup","weight","cpus","io_dev","readahead_kb","scheduler"])

        for line in f:
            line=line.strip()
            if not line: continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            snap = rec.get("snapshot", {})
            io = snap.get("io") or {}
            tw.writerow([
                rec.get("ts_ms"),
                rec.get("pid"),
                rec.get("strategy_type"),
                rec.get("dry_run"),
                snap.get("threads"),
                snap.get("runq_us"),
                snap.get("futex_us"),
                snap.get("page_faults_sum"),
                snap.get("psi_cpu_some"),
                snap.get("psi_mem_some"),
                snap.get("comm_wake"),
                snap.get("comm_futex"),
                snap.get("llc_per_thread"),
                snap.get("total_cpus"),
                snap.get("spikes"),
                io.get("dev"),
                io.get("seq_ratio"),
                len(rec.get("actions", [])),
            ])
            for a in rec.get("actions", []):
                if isinstance(a, str):
                    aw.writerow([rec.get("ts_ms"), rec.get("pid"), a, "", "", "", "", "", "", ""])
                elif isinstance(a, dict):
                    aw.writerow([rec.get("ts_ms"), rec.get("pid"),
                                 a.get("type"),
                                 a.get("pid"),
                                 a.get("cgroup"),
                                 a.get("weight"),
                                 ";".join(map(str, a.get("cpus", []) or [])),
                                 a.get("dev"),
                                 a.get("readahead_kb"),
                                 a.get("scheduler")])
    print("Wrote:", ticks_csv)
    print("Wrote:", actions_csv)

if __name__ == "__main__":
    main()