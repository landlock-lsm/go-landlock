## Onboarding a program onto Landlock

When onboarding a program to use Landlock, first build a rough threat
model and analyze the list of inputs which the program reads and
processes.

A rough checklist:

* [ ] stdin?
* [ ] input files that the program is explicitly opening?
* [ ] configuration files?
* [ ] configuration files used by libraries?
* [ ] incoming network requests
* [ ] responses to outgoing network requests
* [ ] others...?

Consider which of these are potentially attacker-provided and which
are caller-provided.  Inputs that are under control of the calling
process should normally be considered safe.

## Enforce the strongest policy you can

Always strive to enforce the strongest Landlock policy that you can.

With higher Landlock ABI levels, you can enforce stronger policies.

## Find the right place for Landlock enforcement during startup

* Shuffle the steps during program startup so that:
  * Safe inputs (e.g. config files) are opened and processed first,
    unconstrained by Landlock
  * Landlock enforces the narrowest possible sandboxing policy
  * Attacker-provided inputs are processed within the sandbox
* File descriptors opened before Landlock enforcement continue to be
  work after enforcement.  If only a fixed number of attacker-provided
  files are processed by the program, you can open them before
  Landlock enforcement, and start reading them after Landlock
  enforcement.

## Rules for file system access rights

The presets `landlock.ROFiles`, `landlock.RODirs`, `landlock.RWFiles`
and `landlock.RWDirs` provide sensible defaults for common read and
write access to files and directories.

If you have a need for a narrower configuration, see [Custom
Filesystem Rules](custom_fs_rules.md).

Take into account:

* The `LANDLOCK_ACCESS_FS_REFER` right is implicitly denied in ABI v1
  and not included in `RWFiles` and `RWDirs`.  If your program needs
  to link or rename files across different directories, you must
  specifically grant that access right using `FSRule.WithRefer()`.
  When you add that, the enforcement of that Landlock policy will
  require Landlock ABI V2 or higher.
* If your program needs to invoke IOCTLs on newly opened device files,
  you must specifically grant that access right using
  `FSRule.WithIoctlDev()`.

## Rules for network access rights

For comprehensive sandboxing of network access, please augment
Landlock with other mechanisms (e.g., Seccomp-BPF).

* A variety of other protocols outside of TCP are not restrictable
  (see [*socket*(2)](https://man.gnoack.org/2/socket)).

  The bug needs to be fixed in the Linux kernel and is tracked here:
  https://github.com/landlock-lsm/linux/issues/6
* Multipath TCP bind() is not restrictable with Landlock yet, and the
  resulting TCP servers are backwards compatible with vanilla TCP
  clients.

  The bug needs to be fixed in the Linux kernel and is tracked here:
  https://github.com/landlock-lsm/linux/issues/54
