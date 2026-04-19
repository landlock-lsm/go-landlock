# Rule libraries

With Landlock's *composite rules*, you can build reusable libraries of
Landlock rules, without having to resort to custom list appending.

An example is:

```
// DNSLookup bundles the Landlock rules required for basic DNS lookup.
func DNSLookup() landlock.Rule {
  return landlock.CompositeRule(
    landlock.RODirs("/etc"),
    landlock.ConnectTCP(53),
  )
}
```

Noteworthy special case: The empty composite rule
`landlock.CompositeRule()` is a no-op rule which adds no actual rule
to the Landlock ruleset at the C API layer.
