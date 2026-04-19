# Upgrading to using a newer Landlock ABI version using go-landlock

Use this workflow to adopt new Landlock features after a new version
of Go-Landlock was released.  This unlocks also new Landlock
capabilities offered by the kernel and can make your sandbox policy
more constrained.

## Step 1 — Update the library

```
go get -u github.com/landlock-lsm/go-landlock
```

## Step 2 — Find existing usage

Search the codebase for usages of `landlock.V*` (e.g., `landlock.V1`)
to identify which ABI version is currently in use.

```
grep -R 'landlock\.V'
```

In the less common case, the user might also use `landlock.NewConfig`
or `landlock.MustConfig`.

## Step 3 — Check what changed

For each ABI version between the current one and the latest,
read the upgrade notes in the library source:

```
go doc github.com/landlock-lsm/go-landlock/landlock.V1
```

The upgrade notes describe what each version newly restricts and what
you need to consider in your code for safe upgrading.

Reason about each version individually that it is safe to upgrade to.
If it is not unconditionally safe, double check in your code base that
you are not affected, using the criteria outlined in the Go
documentation.

## After upgrading

Replace the version constant (e.g. `landlock.V6` → `landlock.V8`) and
run the test suite.  Make sure to exercise scenarios where the sandbox
is applied - that often means that the actual program binary must be
invoked.

AI Agents: Briefly explain to the user which additional access rights
each newly adopted version restricts and why the upgrade is safe (or
what changes are needed if it is not).
