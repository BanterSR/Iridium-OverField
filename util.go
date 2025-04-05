package main

var dataMap map[string]*session

const (
	buffLen     = 512000
	tcpHeadSize = 2
)

type session struct {
	fromServer bool
	key        string
	data       []byte
}

func addDataMap(key string, data []byte, fromServer bool) {
	if dataMap == nil {
		dataMap = make(map[string]*session)
	}
	if dataMap[key] == nil {
		dataMap[key] = &session{
			fromServer: fromServer,
			key:        key,
			data:       make([]byte, 0),
		}
	}
	dataMap[key].data = append(dataMap[key].data, data...)
}

func getDataMap() map[string]*session {
	return dataMap
}

func (s *session) delData(lens uint16) {
	if uint16(len(s.data)) <= lens {
		s.data = make([]byte, 0)
		return
	}
	s.data = s.data[lens:]
}
