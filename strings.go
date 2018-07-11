package knownhosts

// uniqStrings returns the set of unique strings.
func uniqStrings(input []string) []string {
	u := make([]string, 0, len(input))
	m := map[string]struct{}{}
	for _, val := range input {
		if _, ok := m[val]; !ok {
			m[val] = struct{}{}
			u = append(u, val)
		}
	}
	return u
}
