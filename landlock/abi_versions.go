package landlock

import ll "github.com/landlock-lsm/go-landlock/landlock/syscall"

type abiInfo struct {
	version           int
	supportedAccessFS AccessFSSet
}

var abiInfos = []abiInfo{
	{
		version:           0,
		supportedAccessFS: 0,
	},
	{
		version:           1,
		supportedAccessFS: (1 << 13) - 1,
	},
}

func getSupportedABIVersion() abiInfo {
	v, err := ll.LandlockGetABIVersion()
	if err != nil {
		v = 0 // ABI version 0 is "no Landlock support".
	}
	return abiInfos[v]
}
