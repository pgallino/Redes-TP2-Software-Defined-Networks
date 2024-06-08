from mininet.topo import Topo
from mininet.link import TCLink

class MyTopology(Topo):
    def build(self, num_switches):
        server = self.addHost("server")
        clients = []
        clients.append(self.addHost("h0"))
        clients.append(self.addHost("h1"))
        clients.append(self.addHost("h2"))
        clients.append(self.addHost("h3"))
        switches = []
        switches.append(self.addSwitch("s0"))
        for x in range(1, num_switches):
            new_switch = self.addSwitch("s" + str(x))
            switches.append(new_switch)
            self.addLink(switches[x-1], switches[x], cls=TCLink)
            
        self.addLink(clients[0], switches[0], cls=TCLink)
        self.addLink(clients[1], switches[0], cls=TCLink)
        self.addLink(clients[2], switches[num_switches-1], cls=TCLink)
        self.addLink(clients[3], switches[num_switches-1], cls=TCLink)


topos = {"mytopology": (lambda num_switches: MyTopology(num_switches))}