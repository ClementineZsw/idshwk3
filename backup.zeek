event zeek_init()
	{
	print "Hello, World!";
	}
global justone : int =0;
event http_reply(c: connection, version: string, code: count, reason: string)
{
	if (justone == 0)
	{	print c;
		print c$service;}
	justone=1;
	
}
event zeek_done()
	{
	print "Goodbye, World!";
	}
