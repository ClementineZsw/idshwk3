global ipaddrTable :table[addr] of set[string] = table();
event http_reply(c: connection, version: string, code: count, reason: string)
{
	# print c$id$orig_h;
	# print c$http$user_agent;
	local ip :addr= c$id$orig_h;
	local ua :string = c$http$user_agent;
	if (ip in ipaddrTable ){
		if(c$http$user_agent in ipaddrTable[ip])
		{
		}
		else{
			add ipaddrTable[ip][ua];
		}
	} 
	else
	{
		local temp :set[string] = set();
		ipaddrTable[ip] =temp;
		add ipaddrTable[ip][ua];
	}
}
event zeek_done()
{
	# print ipaddrTable;
	local countnum : int= 0;
	for(ua in ipaddrTable)
	{
		countnum = 0;
		for(s in ipaddrTable[ua])
		{
			countnum = countnum + 1;
		}
		if(countnum > 2)
		{	
			print fmt("%s is a proxy", ua);
		}
	}
}

