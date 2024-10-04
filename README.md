# eBPF Maps State Synchronization across Multi-Node Cluster

When eBPF started gaining popularity, its initial adoption focused primarily on observability, offering developers new ways to monitor and understand their systems. As technology evolved, eBPF’s capabilities expanded significantly. Today, (among other applications) it is widely used for stateful networking solutions such as load balancing, connection tracking, firewalls, and Carrier-Grade NAT (CGNAT).

Deploying these stateful eBPF applications in clusters is essential to avoid single points of failure and ensure high availability. Unlike stateless applications, which do not require synchronization, stateful applications need to maintain consistent state information across all nodes in a cluster like Kubernetes. In stateful applications, state is maintained in the application or in some centralized database but in case of an eBPF application, state or rather information is maintained in the eBPF Maps. And, state of each node needs to be synchronized across the cluster.

But, there are no known synchronization tool or daemon available for eBPF Maps.

On both host, you need run the program using:

```
sudo ./map-sync -ip <IP-of-the-syncing-peer>
```

On any host from the two you can then simulate/trigger actions on eBPF map using:

```
sudo bpftool map
sudo bpftool map update id <MAP-ID> key 0 0 0 0 value 1 0 0 0
sudo bpftool map delete id <MAP-ID> key 0 0 0 0
sudo bpftool map lookup id <MAP-ID> key 0 0 0 0
```
