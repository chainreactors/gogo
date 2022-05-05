package fingers

import "encoding/json"

func LoadHashMapFingers(content []byte) (hashmap map[string]string, err error) {
	err = json.Unmarshal(content, &hashmap)
	if err != nil {
		return nil, err
	}
	return hashmap, nil
}
