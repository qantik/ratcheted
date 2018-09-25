package hibe

//func Test(t *testing.T) {
//	var s gentryySecret
//	s.P0 = &element{pairing.NewG1().Rand()}
//
//	s.Q = make([]*element, 10)
//	for i := 0; i < 10; i++ {
//		s.Q[i] = &element{pairing.NewG1().Rand()}
//	}
//
//	s.A = []byte{1, 2, 3}
//	s.l = 10
//
//	enc, err := json.Marshal(&s)
//	fmt.Println(err)
//
//	var ss gentryySecret
//	err = json.Unmarshal(enc, &ss)
//	fmt.Println(ss.P0.Equals(s.P0.Element))
//	fmt.Println(ss.Q[0].Equals(s.Q[0].Element))
//}
