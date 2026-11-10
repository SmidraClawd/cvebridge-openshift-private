package bridge

const allNamespaces = "*"

// A wildcard is a complete scope, never a namespace name or a glob pattern.
func allNamespaceScope(names []string) bool {
	return len(names) == 1 && names[0] == allNamespaces
}

func validNamespaceScope(names []string, allowAll bool) bool {
	if allowAll && allNamespaceScope(names) {
		return true
	}
	if len(names) == 0 || len(names) > 100 {
		return false
	}
	for _, name := range names {
		if !NS.MatchString(name) {
			return false
		}
	}
	return true
}

func namespaceSubset(requested, allowed []string) bool {
	if !validNamespaceScope(requested, true) {
		return false
	}
	return has(allowed, allNamespaces) || len(intersect(requested, allowed)) == len(unique(requested))
}

func namespaceIntersection(a, b []string) []string {
	if has(a, allNamespaces) {
		return unique(b)
	}
	if has(b, allNamespaces) {
		return unique(a)
	}
	return intersect(a, b)
}
