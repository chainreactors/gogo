package scan

//func winrmScan(target string,result *utils.Result) {
//	//result = model.ProbeTaskResult{ProbeTask: task, Result: "", Err: nil}
//	uri := fmt.Sprintf("http://%s/wsman", target)
//	conn := utils.HttpConn(Delay)
//	req, _ := http.NewRequest("POST", uri, nil)
//	req.Header.Add("Content-Length", "0")
//	req.Header.Add("Keep-Alive", "true")
//	req.Header.Add("Content-Type", "application/soap+xml;charset=UTF-8")
//	req.Header.Add("User-Agent", "Microsoft WinRM Client")
//	req.Header.Add("Authorization", "Negotiate TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==")
//	resp, err := conn.Do(req)
//	if err != nil {
//		return
//	}
//	defer resp.Body.Close()
//
//	ntlminfo := resp.Header.Get("Www-Authenticate")[10:]
//	data, err := base64.StdEncoding.DecodeString(ntlminfo)
//	tinfo := NTLMInfo(data)
//	result.Stat = "OPEN"
//	result.AddNTLMInfo(tinfo)
//}
//
