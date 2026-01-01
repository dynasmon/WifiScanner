# NicoScanner — ARP Network Scanner em C

O **NicoScanner** é uma ferramenta escrita em linguagem C para escanear redes locais utilizando requisições ARP. Ele identifica rapidamente dispositivos conectados, exibindo IPs e endereços MAC dos equipamentos ativos.

---

## Recursos

- Scanner rápido utilizando pacotes ARP.
- Suporte a interfaces Ethernet e Wi-Fi (`eth0`, `wlan0`, `ens33`, etc).
- Salva automaticamente os resultados em um arquivo `results.json`.

---

## Dependências

Instale as dependências necessárias com:

```bash
sudo apt update
sudo apt install build-essential libc-dev
```

---

## Instalação

### 1. Clone o repositório:

```bash
git clone https://github.com/seu-usuario/nicoscanner.git
cd nicoscanner
```

### 2. Compile o código-fonte:

```bash
make
```

### 3. (Opcional) Permitir execução sem `sudo`:

```bash
sudo setcap cap_net_raw=eip ./nico
```

---

## Como usar

Execute o programa com:

```bash
./nico
```

### Exemplo de uso:

```text
Interface (ex: eth0, wlan0): ens33
Prefixo da rede (ex: 192.168.0): 192.168.0
```

---

## Permissões

Caso apareça o erro `socket: Operation not permitted`, execute com `sudo` ou configure as permissões com:

```bash
sudo setcap cap_net_raw=eip ./nico
```

---

## Observações

- O programa utiliza pacotes ARP brutos, portanto pode não funcionar corretamente em ambientes virtuais sem modo "bridge" ativado.
- Idealmente, execute em distribuições Linux reais ou máquinas virtuais com acesso real à rede local.

---


