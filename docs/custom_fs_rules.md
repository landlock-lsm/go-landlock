# Custom Landlock Filesystem Rules

The helper function `landlock.PathAccess(accesses, paths...)`
constructs Landlock filesystem rules with detailed control over all
individual Landlock filesystem access rights.

When constructing these, take the following rules into account:

* A file that has the `LANDLOCK_ACCESS_FS_WRITE_FILE` right must also
  have the `LANDLOCK_ACCESS_FS_TRUNCATE` right, and vice versa.  There
  is some non-obvious functional overlap between these two and they
  are best handled together.
* The `LANDLOCK_ACCESS_FS_REFER` right is implicitly denied in
  Landlock ABI V1. When a rule is asking for this access right,
  enforcement of the ruleset will require Landlock ABI V2 or higher.
