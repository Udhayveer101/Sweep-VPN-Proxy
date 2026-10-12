// A stand-in "update" for the CI end-to-end test. It passes the updater's
// -version check and then never reports that it started, which is what a
// release that hangs at launch looks like. The installed build must put itself
// back.
package main

import (
	"flag"
	"fmt"
	"time"
)

var version = "dev"

func main() {
	show := flag.Bool("version", false, "")
	flag.String("updated-from", "", "")
	flag.Parse()
	if *show {
		fmt.Println(version)
		return
	}
	time.Sleep(time.Hour)
}
