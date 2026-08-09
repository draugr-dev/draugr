package saga

// UpsertComponent appends comp, or unions its surface into an existing same-named one.
//
// The overlay that makes split descriptors work: a shared fragment naming a component's
// repository and a per-product fragment adding its image end up as one component holding both.
//
// Scalars come from the component already present, so the first description of a component wins
// on name, classification and labels. That is why a resolution starts from the root descriptor —
// it keeps the file someone opened authoritative about how exposed a component is, rather than
// letting a fragment merged later quietly reclassify it.
func UpsertComponent(components []Component, comp Component) []Component {
	for i := range components {
		if components[i].Name == comp.Name {
			components[i] = unionComponent(components[i], comp)
			return components
		}
	}
	return append(components, comp)
}

func unionComponent(a, b Component) Component {
	a.Repositories = unionRepositories(a.Repositories, b.Repositories)
	a.Images = unionImages(a.Images, b.Images)
	a.Hosts = unionHosts(a.Hosts, b.Hosts)
	a.Infrastructure = unionInfra(a.Infrastructure, b.Infrastructure)
	return a
}

func unionRepositories(a, b []Repository) []Repository {
	at := map[string]int{}
	for i, r := range a {
		at[r.URL+"@"+r.Revision] = i
	}
	for _, r := range b {
		key := r.URL + "@" + r.Revision
		i, ok := at[key]
		if !ok {
			at[key] = len(a)
			a = append(a, r)
			continue
		}
		// Same repository at the same revision, described twice. Keep both descriptions: paths
		// and ignore are scope, and scope discarded on merge is scanning that quietly stops
		// happening.
		a[i].Paths = unionStrings(a[i].Paths, r.Paths)
		a[i].Ignore = unionStrings(a[i].Ignore, r.Ignore)
	}
	return a
}

// unionStrings appends what is not already present, preserving order.
func unionStrings(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	seen := make(map[string]bool, len(a))
	for _, s := range a {
		seen[s] = true
	}
	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			a = append(a, s)
		}
	}
	return a
}

func unionImages(a, b []Image) []Image {
	at := map[string]int{}
	for i, img := range a {
		at[img.Image] = i
	}
	for _, img := range b {
		if i, ok := at[img.Image]; ok {
			// A survey that just looked at a registry knows the digest; the descriptor that named
			// only a tag does not. Dropping the newer entry throws that away, and a tag-only
			// target is the one whose cached scan can go stale, so the detail is the point.
			if img.Digest != "" {
				a[i].Digest = img.Digest
			}
			continue
		}
		at[img.Image] = len(a)
		a = append(a, img)
	}
	return a
}

func unionHosts(a, b []Host) []Host {
	at := map[string]int{}
	for i, h := range a {
		at[h.URL] = i
	}
	for _, h := range b {
		i, ok := at[h.URL]
		if !ok {
			at[h.URL] = len(a)
			a = append(a, h)
			continue
		}
		// A later survey may have learned what the earlier one could not name.
		if a[i].Name == "" {
			a[i].Name = h.Name
		}
		if a[i].Type == "" {
			a[i].Type = h.Type
		}
	}
	return a
}

func unionInfra(a, b []Infrastructure) []Infrastructure {
	at := map[string]int{}
	for i, in := range a {
		at[in.Kind+"/"+in.Ref] = i
	}
	for _, in := range b {
		key := in.Kind + "/" + in.Ref
		i, ok := at[key]
		if !ok {
			at[key] = len(a)
			a = append(a, in)
			continue
		}
		a[i].Namespaces = mergeNamespaces(a[i].Namespaces, in.Namespaces)
	}
	return a
}

// mergeNamespaces combines two namespace scopes, where **empty means the whole cluster**.
//
// So empty is not the identity of this operation, it is the widest value: an entry covering the
// whole cluster stays covering the whole cluster, even when merged with one naming three
// namespaces. Unioning the lists literally would narrow it, and a survey that quietly reduced
// what the next scan looks at is the dangerous direction for this to be wrong in — nobody reads a
// descriptor to check that it still covers what it covered yesterday.
//
// Widening is safe and is what a survey of the whole cluster means, so it happens without comment.
// Narrowing is a decision, and `draugr survey` says when it declined to make one on your behalf.
func mergeNamespaces(a, b []string) []string {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(a))
	for _, ns := range a {
		seen[ns] = true
	}
	for _, ns := range b {
		if !seen[ns] {
			seen[ns] = true
			a = append(a, ns)
		}
	}
	return a
}

// NarrowsScope reports whether merging frag into model would have narrowed an infrastructure
// target's namespaces, had the wider scope not been kept.
//
// Exported so the command that merges can say so. The merge itself keeps the wider scope, which
// is the safe answer and also the surprising one: somebody who passed `--namespace` is entitled
// to know their flag did not reach the descriptor.
func NarrowsScope(model *Model, frag Fragment) []string {
	wide := map[string]bool{}
	for _, c := range model.Components {
		for _, in := range c.Infrastructure {
			if len(in.Namespaces) == 0 {
				wide[c.Name+"/"+in.Kind+"/"+in.Ref] = true
			}
		}
	}
	var out []string
	for _, c := range frag.Components {
		for _, in := range c.Infrastructure {
			if len(in.Namespaces) > 0 && wide[c.Name+"/"+in.Kind+"/"+in.Ref] {
				out = append(out, c.Name+" ("+in.Ref+")")
			}
		}
	}
	return out
}
