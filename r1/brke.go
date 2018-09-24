// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package r1

import "bytes"

type BRKE struct {
	srke     *SRKE
	sender   *srkeSender
	receiver *srkeReceiver

	ots ots
}

func NewBRKE(srke *SRKE, sender *srkeSender, receiver *srkeReceiver, ots ots) *BRKE {
	return &BRKE{srke: srke, sender: sender, receiver: receiver, ots: ots}
}

func (b *BRKE) send(ad []byte) (ko, vfk, sigma []byte, c1, c2 [][]byte) {
	vfk, sgk := b.ots.GenerateKeys()

	ad = append(ad, vfk...)

	ko, c1 = b.srke.senderSend(b.sender, ad)
	c2 = b.srke.receiverSend(b.receiver, ad)
	sigma = b.ots.Sign(sgk, append(bytes.Join(c1, nil), bytes.Join(c2, nil)...))

	return
}

func (b *BRKE) receive(ad, vfk, sigma []byte, c1, c2 [][]byte) (ko []byte) {
	ad = append(ad, vfk...)

	if !b.ots.Verify(vfk, append(bytes.Join(c1, nil), bytes.Join(c2, nil)...), sigma) {
		panic("unable to verify ots")
	}

	b.srke.senderReceive(b.sender, ad, c2)
	ko = b.srke.receiverReceive(b.receiver, ad, c1)

	return
}
