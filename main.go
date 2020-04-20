package main

// Block in the chain
type Block struct {
	Index     int
	Timestamp string
	BPM       int
	Hash      string
	PrevHash  string
}

// Blockchain represents a simulated BC
var Blockchain []Block

func main() {

}
