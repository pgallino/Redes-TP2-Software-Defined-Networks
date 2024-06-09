# Redes-TP2-Software-Defined-Networks

## Requisitos Previos

- Python 3
- Mininet

## Instrucciones

**Ejecutar POX:**

   Para ejecutar POX, hay que utilizar el siguiente comando:

   ```bash
   python3 pox.py log.level --DEBUG openflow.of_01 forwarding.l2_learning firewall
   ```

**Ejecutar Mininet:**

   Para ejecutar Mininet, hay que utilizar el siguiente comando:

   ```bash
   sudo mn --custom topologia.py --topo mytopology,n --arp --switch ovsk --controller remote
   ```

  Siendo n el número de switches
