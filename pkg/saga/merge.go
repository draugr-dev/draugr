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
	seen := make(map[string]bool)
	for _, r := range a {
		seen[r.URL+"@"+r.Revision] = true
	}
	for _, r := range b {
		if key := r.URL + "@" + r.Revision; !seen[key] {
			seen[key] = true
			a = append(a, r)
		}
	}
	return a
}

func unionImages(a, b []Image) []Image {
	seen := make(map[string]bool)
	for _, img := range a {
		seen[img.Image] = true
	}
	for _, img := range b {
		if !seen[img.Image] {
			seen[img.Image] = true
			a = append(a, img)
		}
	}
	return a
}

func unionHosts(a, b []Host) []Host {
	seen := make(map[string]bool)
	for _, h := range a {
		seen[h.URL] = true
	}
	for _, h := range b {
		if !seen[h.URL] {
			seen[h.URL] = true
			a = append(a, h)
		}
	}
	return a
}

func unionInfra(a, b []Infrastructure) []Infrastructure {
	seen := make(map[string]bool)
	for _, in := range a {
		seen[in.Kind+"/"+in.Ref] = true
	}
	for _, in := range b {
		if key := in.Kind + "/" + in.Ref; !seen[key] {
			seen[key] = true
			a = append(a, in)
		}
	}
	return a
}
