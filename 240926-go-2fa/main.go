package main

import (
	"bufio"
	"bytes"
	"fmt"
	"image/png"
	"os"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func display(key *otp.Key, data []byte) {
	fmt.Printf("Issuer: %s\n", key.Issuer())
	fmt.Printf("Account Name: %s\n", key.AccountName())
	fmt.Printf("Secret: %s\n", key.Secret())
	fmt.Println("Writing PNG to qr-code.png....")
	os.WriteFile("qr-code.png", data, 0644)
	fmt.Println("")
	fmt.Println("Please add your TOTP to your OTP Application now!")
	fmt.Println("")
}

func prompForPasscode() string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter Passcode: ")
	text, _ := reader.ReadString('\n')
	return text
}

func main() {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Example.com",
		AccountName: "user@example.com",
	})
	if err != nil {
		panic(err)
	}

	// Conver TOTP key into a PNG
	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		panic(err)
	}
	png.Encode(&buf, img)

	// Display the QR code to the user
	display(key, buf.Bytes())

	// Now validate the user's successfully added the passcode.
	fmt.Println("Validaing TOTP...")
	passcode := prompForPasscode()
	valid := totp.Validate(passcode, key.Secret())
	if valid {
		println("Valid passcode")
		os.Exit(0)
	} else {
		println("Invalid passcode!")
		os.Exit(1)
	}
}
