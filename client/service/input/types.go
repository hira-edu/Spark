package input

// PointerEvent represents normalized pointer data.
type PointerEvent struct {
	Action string
	Button int
	DeltaY int
	X      int
	Y      int
}

// KeyboardEvent represents normalized keyboard data.
type KeyboardEvent struct {
	Action   string
	Key      string
	Code     string
	KeyCode  int
	Alt      bool
	Ctrl     bool
	Shift    bool
	Meta     bool
	Repeat   bool
	Location int
}
