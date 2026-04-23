import magic  #importa biblioteca magic
import shutil # para mover arquivos
import os  #comunicação com o OS
from pathlib import Path  #blibioteca pathlib 
from datetime import datetime #Para data e hora

#verificaçao do caminho 
#(objeto) PATH
#  Definição de classe programa ou maquina
class DeepCheck:
    def __init__(self, caminho_do_arquivo): #self Tudo que estiver dentro funciona
        self.arquivo = Path(caminho_do_arquivo)  #estancia
        #  Dicionário ou "WhiteList"
        self.De_PARA = {  #EXTENSOES
            "image/jpeg": [".jpg", ".jpeg", ".jpe"],
            "image/png": [".png"],
            "application/pdf": [".pdf"],
            "application/x-sh": [".sh"],
            "text/plain": [".txt"]
        }
#verificação do arquivo
    def verificar_arquivo(self):
        return self.arquivo.exists() and self.arquivo.is_file()
#is_file() verifica se é arquivo ou pasta.
#.exists() função que existe na biblioteca pathlib do objeto que criamos (Path) , verifica se o arquivo existe 
#.exist() checa se o caminho é real
#is_file() verifica se é arquivo
# self serve para o programa enxergar o que esta dentro da classe 
#identificador de tipo
    def identificar_type_real(self):
        detector = magic.Magic(mime=True) 
#Objeto detector com mime=True para ele retornar 
# Textos padroes como 'image/png' ou 'application/pdf'
#MIME  vem da biblioteca python-magic
#padrão mundial (Multipurpose Internet Mail Extensions)
        return detector.from_file(str(self.arquivo))
#biblioteca antiga receber uma str ao inves do objeto Path
#.from_file() lê o cabeçalho do arquivo no disco

    def obter_extensao_decla(self): #funçao de extençao declarada
        return self.arquivo.suffix.lower()
 #suffix vem do pathlib ele pega tudo depois do '.' 'png'
 #suffix pega tudo que vem depois do ultimo ponto ex : .jpg
#.lower() transforma tudo em minusculo para nao ter diferença entre JPG e jpg
    def validar_spoofing(self, tipo_real, extensao_declarada):
    #função de validação
        if tipo_real == "application/x-dosexec" and extensao_declarada != ".exe":
            #mesmo fora da whitelist ja barra antes se tiver camuflado
            return "🚨 ALERTA CRÍTICO: Executável camuflado detectado! Risco de Malware."
        if tipo_real in self.De_PARA: # se o tipo real tiver dentro da lista
            extensoes_validas = self.De_PARA[tipo_real] #guarda nas validas
            if extensao_declarada in extensoes_validas: # e a extensao for valida
                return "✅ Sucesso! O arquivo é legítimo." #boa garoto  
            else:  #se não cuidado
                return f"🚨 ALERTA DE SPOOFING: O conteúdo é {tipo_real}, e sua extensão é {extensao_declarada}."
        else: #fora da whitelist
            return "🔍 ALERTA: Tipo de arquivo não mapeado na Whitelist."
# --- BLOCO PRINCIPAL DE EXECUÇÃO ---
if __name__ == "__main__": #meu butaozin de ligar
    Base_DIR = Path(__file__).resolve().parent #diretorio pai base , e raiz de diretorio
#pq tive puta trabalho :V  # descobre onde ta o arquivo 
    pasta_alvo = Base_DIR / "arquivos_para_teste" #pasta que sera analisada
    pasta_quarentena = Base_DIR / "QUARENTENA" #Defino a pasta de quarentena
    pasta_quarentena.mkdir(exist_ok=True) #aqui caso nao exista que ela crie, e se existir nao dé erro
    lista_suspeitos = [] # Criação da lista para guardar las informaciones
    log_name = f"log_analise{datetime.now().strftime('%d_%m_%Y, %H_%M_%S')}.txt" #criaçao do log
    with open (log_name, "w", encoding="utf-8") as log_file: #abre ou cria o arquivo #para escrita 
        log_file.write(f'RELATÓRIO DE SEGURANÇA - {datetime.now()}\n') #o cabeçudo
        log_file.write('='*50 + '\n') #cabecinha

        if not pasta_alvo.exists(): #caso nao exista a pasta_alvo ela pede pra tu cria ne
            print(f"Crie a pasta '{pasta_alvo}' para testar o scanner!")
        else:
            print(f"=== Iniciando Varredura na pasta: {pasta_alvo} ===\n") #se ja existir bora de analise
        
        for item in pasta_alvo.iterdir(): #para cada item em pasta_alvo da uma olhada
            if item.is_file(): #se esse item e um arquivo nao um diretorio
                try: #tente
                    detector = DeepCheck(item) #checar  item por item
                    tipo = detector.identificar_type_real() #identifica o tipo
                    ext = detector.obter_extensao_decla() #a extensão
                    resultado = detector.validar_spoofing(tipo, ext) #define o resultado final

                    if "ALERTA" in resultado.upper(): #encontrar o alerta na mensagi
                        msg_erro = f"[{datetime.now()}] SUSPEITO: {item.name} | Motivo: {resultado}"
                        lista_suspeitos.append(msg_erro) #adiciono a lista de suspeitos a mensagem dado o nome e o resultado
                        log_file.write(msg_erro + "\n")#enviando para o arquivo log a mensagem.
                        shutil.move(str(item), str(pasta_quarentena / item.name))#como sera movido
                        #pega o item com o nome que esta e joga na pasta quarentena
                        print(f"⚠️ {item.name} MOVIDO PARA QUARENTENA!")#imprima movido a quarentena
                    else:
                        log_file.write(f"[{datetime.now()}] LIMPO: {item.name}\n") #tudo ok! garfanhoto

                except Exception as e:
                    log_file.write(f"ERRO: {item.name} - {e}\n") #aqui foi definida um exceção caso  aconteça algum erro

    print(f"\n✅ Análise concluída. Log gerado: {log_name}")
    # --- RESUMO FINAL ---
print("\n=== RESUMO ===")
if len(lista_suspeitos) > 0:    
    print(f"Foram encontrados {len(lista_suspeitos)} arquivos suspeitos:")
    for suspeito in lista_suspeitos:
        print(f"⚠️ {suspeito}")
    else:
        print("✅ Nenhum spoofing detectado na pasta. Tudo limpo!")

#definido meios para alerta, log e emails , como hora data de analise
# e tbm um meio de mover esses arquivos para uma especie de Quarentena
#uso de 3 bibiliotecas a mais ja existentes no python 
#shutil (para mover pastas)
# datetime (para a hora e data)
#smtplib (para email-s)

#def enviar_email_alerta(lista_problemas): #função futura para alerta de email
#    msg = EmailMessage() #define a mensagem
#    msg['Subject'] = '🚨 ALERTA DE SEGURANÇA: Arquivos Suspeitos Detectados'
#    msg['From'] = 'seu_email@gmail.com' #de onde vai ser enviado
#    msg['To'] = 'seu_email@gmail.com' # pra quem
    
#    corpo = "O DeepCheck detectou os seguintes arquivos suspeitos:\n\n" #lo tronco
#    corpo += "\n".join(lista_problemas) #para junta a lista de problemas
#    msg.set_content(corpo) #define o corpo da msg
#    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp: #abre pra nois amor  #uso de smtp 
#        smtp.login('seu_email@gmail.com', 'SUA_SENHA_DE_APP_AQUI') #aqui pra tu fazer login cuidado com a senha ":C"
#        smtp.send_message(msg) #para enviar la mensagem
#    print("📧 E-mail de alerta enviado com sucesso!")



