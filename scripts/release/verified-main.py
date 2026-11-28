#!/usr/bin/env python3
"""Reuse recent authoritative main CI, or request full release verification.

No artifacts are reused. API errors, incomplete bounded responses and ambiguous
proof select the existing full verification path.
"""
import datetime as dt
import json
import os
import re
import subprocess

REPOSITORY = 'bherila/auth-manager'
WORKFLOW = '.github/workflows/ci.yml'
REQUIRED_JOBS = {'ci', 'MariaDB engine tests', 'Reproducible release artifact'}
MAX_AGE = dt.timedelta(hours=24)


def api(path):
    result = subprocess.run(['gh', 'api', path], check=True, capture_output=True,
                            text=True, timeout=10)
    return json.loads(result.stdout)


def recent_success(run, commit, workflow_id, now):
    started = dt.datetime.fromisoformat(run['run_started_at'].replace('Z', '+00:00'))
    completed = dt.datetime.fromisoformat(run['updated_at'].replace('Z', '+00:00'))
    return (run['repository']['full_name'] == REPOSITORY
            and run['head_repository']['full_name'] == REPOSITORY
            and run['workflow_id'] == workflow_id and run['path'] == WORKFLOW
            and run['event'] == 'push' and run['head_branch'] == 'main'
            and run['head_sha'] == commit and run['status'] == 'completed'
            and run['conclusion'] == 'success' and type(run['id']) is int
            and type(run['run_attempt']) is int and run['run_attempt'] > 0
            and started <= completed <= now and dt.timedelta(0) <= now - started <= MAX_AGE)


def select_proof(commit, fetch=api, now=None):
    if not re.fullmatch('[0-9a-f]{40}', commit):
        return None
    now = now or dt.datetime.now(dt.timezone.utc)
    try:
        workflow = fetch(f'repos/{REPOSITORY}/actions/workflows/ci.yml')
        if workflow['path'] != WORKFLOW or type(workflow['id']) is not int:
            return None
        response = fetch(f'repos/{REPOSITORY}/actions/workflows/{workflow["id"]}/runs'
                         f'?branch=main&event=push&head_sha={commit}&status=success&per_page=20')
        runs = response['workflow_runs']
        if response['total_count'] != len(runs) or len(runs) > 20:
            return None
        for candidate in runs:
            if not recent_success(candidate, commit, workflow['id'], now):
                continue
            path = f'repos/{REPOSITORY}/actions/runs/{candidate["id"]}'
            run = fetch(path)
            if not recent_success(run, commit, workflow['id'], now):
                return None
            jobs = fetch(f'{path}/attempts/{run["run_attempt"]}/jobs?per_page=100')
            if jobs['total_count'] != len(jobs['jobs']) or len(jobs['jobs']) > 100:
                return None
            # Attempt-specific jobs deliberately reject inherited/skipped lanes.
            for name in REQUIRED_JOBS:
                matches = [job for job in jobs['jobs'] if job['name'] == name]
                if (len(matches) != 1 or matches[0]['run_id'] != run['id']
                        or matches[0]['run_attempt'] != run['run_attempt']
                        or matches[0]['head_sha'] != commit
                        or matches[0]['status'] != 'completed'
                        or matches[0]['conclusion'] != 'success'):
                    return None
            else:
                # A rerun begun while reading the jobs invalidates the proof.
                final = fetch(path)
                if (final == run and recent_success(final, commit, workflow['id'], now)):
                    return {'source_sha': commit, 'run_id': run['id'],
                            'attempt': run['run_attempt'], 'workflow_id': workflow['id']}
                return None
        return None
    except (KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError):
        return None


def main():
    proof = select_proof(os.environ['COMMIT'])
    evidence = (f"Main CI run {proof['run_id']}, attempt {proof['attempt']}, "
                f"workflow {proof['workflow_id']}, source {proof['source_sha']}"
                if proof else 'Full verification on the tagged commit')
    with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
        output.write(f'reuse={str(proof is not None).lower()}\n')
        output.write(f'evidence={evidence}\n')
    with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as summary:
        summary.write(f'### Release verification\n\n{evidence}\n')
    print(evidence)


if __name__ == '__main__':
    main()
