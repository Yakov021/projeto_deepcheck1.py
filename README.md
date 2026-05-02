# projeto_ExtCheck_Antispoofing
# 🔍 ExtCheck — Anti Spoofing de Arquivos

ExtCheck é um script Python de anti-spoofing desenvolvido para identificar 
arquivos que tentam camuflar sua verdadeira identidade através da extensão declarada.

Ele lê os **Magic Bytes** de cada arquivo e valida sua real identidade 
pelo padrão MIME — movendo arquivos suspeitos para quarentena e gerando 
um log detalhado para análise posterior.

---

## 💡 Motivação

Este projeto nasceu de uma análise real de tráfego de rede sobre o malware 
**WarmCookie** — um trojan que se camuflou como `.txt` e, após executado, 
realizou tentativas de conexão remota, escalação lateral, e gerou ruído 
de acesso a organizações como Microsoft e Adobe para enganar o firewall.

Repositório da análise: [Warmcookie_wireshark](link_aqui)

---

## ⚙️ Tecnologias

| Tecnologia | Uso |
|---|---|
| Python 3.0+ | Linguagem base |
| python-magic | Leitura dos Magic Bytes via padrão MIME |
| shutil | Movimentação de arquivos para quarentena |
| pathlib | Manipulação de caminhos |
| datetime | Geração de timestamps no log |

> `shutil`, `pathlib` e `datetime` já vêm nativos no Python.  
> Apenas o `python-magic` precisa ser instalado.

---

## 🚀 Como Usar

**1. Clone o repositório**
```bash
git clone https://github.com/Yakov021/projeto_deepcheck1.py
```

**2. Crie e ative o ambiente virtual**
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

**3. Instale a dependência**
```bash
pip install python-magic
```

**4. Crie a pasta e adicione os arquivos para teste**
arquivos_para_teste/

**5. Execute**
```bash
python projeto.py
```

---

## 📁 Output

- Arquivos suspeitos são movidos para a pasta `QUARENTENA/`
- Um arquivo de log é gerado com timestamp, nome do arquivo e motivo da suspeita
