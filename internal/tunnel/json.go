package tunnel

import "encoding/json"

func mustJSON(f Frame) []byte {
	data, _ := json.Marshal(f)
	return data
}

func parseJSON(b []byte) (Frame, error) {
	var f Frame
	err := json.Unmarshal(b, &f)
	return f, err
}
