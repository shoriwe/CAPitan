package objects

import "strconv"

type (
	Topology struct {
		numberOfVertices   int
		numberOfEdges      int
		numberOfCategories int
		nextVertexId       int
		Categories         []string
		Edges              map[string]map[string]struct{}
		Vertices           map[string]struct {
			Id       string
			Name     string
			Category int
		}
	}
)

func NewTopology() *Topology {
	return &Topology{
		numberOfVertices:   0,
		numberOfEdges:      0,
		numberOfCategories: 0,
		nextVertexId:       1,
		Categories:         nil,
		Edges:              map[string]map[string]struct{}{},
		Vertices: map[string]struct {
			Id       string
			Name     string
			Category int
		}{},
	}
}

func (topology *Topology) AddVertex(name string) bool {
	if _, found := topology.Vertices[name]; !found {
		topology.Vertices[name] = struct {
			Id       string
			Name     string
			Category int
		}{
			Id:       strconv.Itoa(topology.nextVertexId),
			Name:     name,
			Category: topology.nextVertexId - 1,
		}
		topology.Categories = append(topology.Categories, name)
		topology.nextVertexId++
		topology.numberOfVertices++
		topology.numberOfCategories++
		return true
	}
	return false
}

func (topology *Topology) addEdge(from, to string) bool {
	if destinations, found := topology.Edges[from]; found {
		if _, destinationFound := destinations[to]; !destinationFound {
			destinations[to] = struct{}{}
			topology.numberOfEdges++
			return true
		}
	} else {
		topology.Edges[from] = map[string]struct{}{to: {}}
		topology.numberOfEdges++
		return true
	}
	return false
}

func (topology *Topology) AddEdge(from, to string) bool {
	topology.AddVertex(from)
	topology.AddVertex(to)
	return topology.addEdge(from, to)
}

func (topology *Topology) Options() interface{} {
	var vertices = make([]struct {
		Id       string  `json:"id"`
		Name     string  `json:"name"`
		Category int     `json:"category"`
		Value    float64 `json:"value"`
	}, topology.numberOfVertices)
	dataIndex := 0
	for _, vertex := range topology.Vertices {
		vertices[dataIndex] = struct {
			Id       string  `json:"id"`
			Name     string  `json:"name"`
			Category int     `json:"category"`
			Value    float64 `json:"value"`
		}{
			Id:       vertex.Id,
			Name:     vertex.Name,
			Category: vertex.Category,
			Value:    1,
		}
		dataIndex++
	}
	var edges = make([]struct {
		Source string `json:"source"`
		Target string `json:"target"`
	}, topology.numberOfEdges)
	edgesIndex := 0
	for source, targets := range topology.Edges {
		for target := range targets {
			edges[edgesIndex] = struct {
				Source string `json:"source"`
				Target string `json:"target"`
			}{
				Source: topology.Vertices[source].Id,
				Target: topology.Vertices[target].Id,
			}
			edgesIndex++
		}
	}
	var categories = make([]struct {
		Name string `json:"name"`
	}, topology.numberOfCategories)
	for categoryIndex, category := range topology.Categories {
		categories[categoryIndex] = struct {
			Name string `json:"name"`
		}{
			Name: category,
		}
	}
	return struct {
		Vertices []struct {
			Id       string  `json:"id"`
			Name     string  `json:"name"`
			Category int     `json:"category"`
			Value    float64 `json:"value"`
		}
		Edges []struct {
			Source string `json:"source"`
			Target string `json:"target"`
		}
		Categories []struct {
			Name string `json:"name"`
		}
	}{
		Vertices:   vertices,
		Edges:      edges,
		Categories: categories,
	}
}
