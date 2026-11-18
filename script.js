
// ======================================
// PROJETO: PROTEÇÃO DE INFORMAÇÕES
// Autora: Sara Laís Kmiecik
// ======================================

// Converte bytes para Base64
function paraBase64(bytes) {
    let binario = "";
    bytes.forEach(byte => {
        binario += String.fromCharCode(byte);
    });
    return btoa(binario);
}

// Converte Base64 para bytes
function deBase64(base64) {
    const binario = atob(base64);
    return Uint8Array.from(binario, c => c.charCodeAt(0));
}

// Cria uma chave usando a senha e PBKDF2
async function criarChave(senha, salt) {
    const encoder = new TextEncoder();

    const material = await crypto.subtle.importKey(
        "raw",
        encoder.encode(senha),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 200000,
            hash: "SHA-256"
        },
        material,
        {
            name: "AES-GCM",
            length: 256
        },
        false,
        ["encrypt", "decrypt"]
    );
}

// ======================================
// CRIPTOGRAFAR MENSAGEM
// ======================================

async function criptografar() {
    try {
        const mensagem = document.getElementById("mensagem").value;
        const senha = document.getElementById("senha").value;

        if (!mensagem || !senha) {
            alert("Digite uma mensagem e uma senha!");
            return;
        }

        const encoder = new TextEncoder();

        // Salt e vetor de inicialização aleatórios
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));

        const chave = await criarChave(senha, salt);

        const dados = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            chave,
            encoder.encode(mensagem)
        );

        const resultado = {
            algoritmo: "AES-256-GCM",
            salt: paraBase64(salt),
            iv: paraBase64(iv),
            dados: paraBase64(new Uint8Array(dados))
        };

        document.getElementById("resultado").value =
            JSON.stringify(resultado);

        alert("Mensagem criptografada com sucesso!");

    } catch (erro) {
        console.error(erro);
        alert("Erro ao criptografar a mensagem.");
    }
}

// ======================================
// DESCRIPTOGRAFAR MENSAGEM
// ======================================

async function descriptografar() {
    try {
        const mensagem = document.getElementById("mensagem").value;
        const senha = document.getElementById("senha").value;

        if (!mensagem || !senha) {
            alert("Informe o texto criptografado e a senha!");
            return;
        }

        const objeto = JSON.parse(mensagem);

        if (
            objeto.algoritmo !== "AES-256-GCM" ||
            !objeto.salt ||
            !objeto.iv ||
            !objeto.dados
        ) {
            throw new Error("Formato inválido.");
        }

        const salt = deBase64(objeto.salt);
        const iv = deBase64(objeto.iv);
        const dados = deBase64(objeto.dados);

        if (salt.length !== 16 || iv.length !== 12) {
            throw new Error("Dados inválidos.");
        }

        const chave = await criarChave(senha, salt);

        const textoOriginal = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            chave,
            dados
        );

        const decoder = new TextDecoder();

        document.getElementById("resultado").value =
            decoder.decode(textoOriginal);

        alert("Mensagem descriptografada com sucesso!");

    } catch (erro) {
        console.error(erro);
        alert("Não foi possível descriptografar. Verifique a senha e o texto.");
    }
}

// ======================================
// GERAR HASH SHA-256
// ======================================

async function gerarHash() {
    try {
        const texto = document.getElementById("textoHash").value;

        if (!texto) {
            alert("Digite um texto para gerar o hash!");
            return;
        }

        const encoder = new TextEncoder();

        const dados = encoder.encode(texto);

        const hash = await crypto.subtle.digest(
            "SHA-256",
            dados
        );

        const hashArray = Array.from(new Uint8Array(hash));

        const hashHexadecimal = hashArray
            .map(byte => byte.toString(16).padStart(2, "0"))
            .join("");

        document.getElementById("hashResultado").value =
            hashHexadecimal;

    } catch (erro) {
        console.error(erro);
        alert("Erro ao gerar o hash.");
    }
}

// ======================================
// COPIAR RESULTADOS
// ======================================

async function copiarResultado() {
    const texto = document.getElementById("resultado").value;

    if (!texto) {
        alert("Não existe resultado para copiar!");
        return;
    }

    try {
        await navigator.clipboard.writeText(texto);
        alert("Resultado copiado!");
    } catch (erro) {
        alert("Não foi possível copiar o resultado.");
    }
}

async function copiarHash() {
    const texto = document.getElementById("hashResultado").value;

    if (!texto) {
        alert("Gere um hash primeiro!");
        return;
    }

    try {
        await navigator.clipboard.writeText(texto);
        alert("Hash copiado!");
    } catch (erro) {
        alert("Não foi possível copiar o hash.");
    }
}
