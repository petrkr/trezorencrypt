/*
  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package main

import (
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"syscall"

	"github.com/golang/protobuf/proto"
	"github.com/pborman/getopt/v2"
	"github.com/trezor/trezord-go/trezorapi"
	"github.com/trezor/trezord-go/trezorapi/trezorpb"
	"github.com/trezor/trezord-go/trezorapi/trezorpb/trezorpbcall"
)

var (
	iv = []byte("trezorEncrypt IV")
)

func usage() int {
	getopt.Usage()
	return int(syscall.EINVAL)
}

func checkError(err error) {
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, "Got error:", err)
	os.Exit(-1)
}

func makeStringPointer(v string) *string {
	return &v
}

func makeBoolPointer(v bool) *bool {
	return &v
}

func trezorCall(
	ctx context.Context,
	api *trezorapi.API,
	pbMessage proto.Message,
	session string,
	debugLink bool,
) (proto.Message, error) {
	res, err := trezorpbcall.Call(ctx, api, pbMessage, session, debugLink)

	switch data := res.(type) {
	case *trezorpb.ButtonRequest:
		return trezorCall(ctx, api, &trezorpb.ButtonAck{}, session, debugLink)

	case *trezorpb.PinMatrixRequest:
		fmt.Println("PIN Request")
		cmd := exec.Command("trezor-askpass", "PIN")
		cmd.Stdin = os.Stdin
		cmd.Stderr = os.Stderr

		out, err := cmd.Output()

		if err != nil {
			panic(err)
		}

		pin := string(out)

		return trezorCall(ctx, api, &trezorpb.PinMatrixAck{Pin: &pin}, session, debugLink)

	case *trezorpb.PassphraseRequest:
		if data.OnDevice != nil && *data.OnDevice {
			fmt.Fprintln(os.Stderr, "Passphrase requested on device")
			return trezorCall(ctx, api, &trezorpb.PassphraseAck{Passphrase: nil}, session, debugLink)
		}

		cmd := exec.Command("trezor-askpass", "Passphrase")
		cmd.Stdin = os.Stdin
		cmd.Stderr = os.Stderr

		out, _ := cmd.Output()
		pass := string(out)

		return trezorCall(ctx, api, &trezorpb.PassphraseAck{Passphrase: &pass}, session, debugLink)

	case *trezorpb.PassphraseStateRequest:
		return trezorCall(ctx, api, &trezorpb.PassphraseStateAck{}, session, debugLink)
	}

	return res, err
}

func main() {
	helpFlag := getopt.BoolLong("help", 'h', "print help message")

	getopt.Parse()

	if *helpFlag {
		usage()
		os.Exit(0)
	}

	trezorAPI, err := trezorapi.New(trezorapi.AddUDPPort(21324))
	if err != nil {
		panic(err)
	}

	// enumerating
	ds, err := trezorAPI.Enumerate()
	if err != nil {
		panic(err)
	}

	if len(ds) < 1 {
		fmt.Fprintln(os.Stderr, "No TREZOR device(s) found")
		os.Exit(1)
	}

	d := ds[0]

	// acquiring
	debugLink := false
	session, err := trezorAPI.Acquire(d.Path, d.Session, debugLink)
	if err != nil {
		panic(err)
	}

	// calling, automatically marshaling/demarshaling PB messages
	res, err := trezorCall(
		context.Background(),
		trezorAPI,
		&trezorpb.Initialize{},
		session,
		debugLink,
	)

	if err != nil {
		panic(err)
	}

	switch typed := res.(type) {
	case *trezorpb.Features:
		fmt.Printf("Device ID: %s\n", *typed.DeviceId)
	default:
		fmt.Println("Unknown type.")
	}

	value := []byte("TEST VALUE")
	paddedValue := make([]byte, 16*int(math.Ceil(float64(len(value))/16)))
	copy(paddedValue, value)

	res, err = trezorCall(
		context.Background(),
		trezorAPI,
		&trezorpb.CipherKeyValue{
			Key:          makeStringPointer("TEST KEY"),
			Value:        paddedValue,
			Encrypt:      makeBoolPointer(true),
			AskOnDecrypt: makeBoolPointer(true),
			AskOnEncrypt: makeBoolPointer(true),
		},
		session,
		debugLink,
	)

	if err != nil {
		panic(err)
	}

	switch data := res.(type) {
	case *trezorpb.CipheredKeyValue:
		fmt.Printf("Data: %s", string(data.Value))
	case *trezorpb.Failure:
		fmt.Printf("Failure: %s\n", *data.Message)
	default:
		fmt.Println("Unknown type.")
	}

	// releasing
	err = trezorAPI.Release(session, debugLink)
	if err != nil {
		panic(err)
	}
}
