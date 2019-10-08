# VMwareHorizonPoolsReport

This repo contains a study script collecting VMware Horizon (pod-aware) pools session information with output as xml. Study script means it was not well maintained.

Get-VMwareHorizonReport.ps1 collects VMware Horizon Pools desktop information from a Connection Server. The script requires run as administrator. It remediates necessary VMware PowerCLI 6.5.4 prerequisites. You can change the input values in the script:

Define VMware Horizon View Connection Server Name, domain name, username (once with fqdn and once the username only) and password.
$hzConn="podb-con-in-1" 
$hzDomain="domain"
$hzUser="serviceadmin@domain.local"
$hzUserName="serviceadmin"
$hzPassword="Secure123!"

A pool is defined by ConnectionServerName\Poolname. 
$hzPools="podb-con-in-1\PoolA1B"

A pair pool in a pod must be signalized as ConnectionServer1Name\Pool1name=ConnectionServer2Name\Pool2name
$hzPools="podb-con-in-1\PoolA1B=poda-con-in-1\PoolA1A"

You can define up to three pools.
$hzPools="podb-con-in-1\PoolA1B=poda-con-in-1\PoolA1A;podb-con-in-1\PoolB1B=poda-con-in-1\PoolB1A;podb-con-in-1\Pool-C"


VMwareHorizonPoolOutput.xml contains a sample xml output. Connection Server Health Connection Data contains Connections, ConnectionsHigh, ViewComposerConnections, TunneledSessions, etc.

