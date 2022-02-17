# Repositório para demonstrar algumas formas de prevenir ataques de Cross-site Scripting

Neste repositório, apresento algumas bibliotecas que podem ajudar a proteger uma aplicação contra a vulnerabilidade Cross-site Scripting, também conhecida como XSS.

# Como prevenir XSS em aplicações Node.js?

Neste repositório, apresento algumas formas de proteger uma aplicação Node.js contra a vulnerabilidade Cross-site Scripting, também conhecida como XSS.

Para mitigar este tipo de ataque é importante reduzir ao máximo a quantidade de inputs não confiáveis de usuário e garantir políticas robustas contra scripts executados no site. 

Vamos a algumas ações que podemos ter no desenvolvimento da aplicação:

### Validação e Sanitização:

Podemos começar com a validação e sanitização dos dados, ou seja, todas as requisições devem checar se os dados enviados pelo usuário estão no formato correto e filtrá-los para que sejam enviados como dado e não como código. 

Existem algumas bibliotecas que realizam validação e sanitização e se sua aplicação Node.js utiliza o Express, é possível utilizar a [Express-Validator](https://github.com/express-validator/express-validator). Ela reúne um conjunto de middlewares que validam os dados antes de serem efetivamente persistidos no banco de dados.  

Exemplo:

```js
const express = require('express');
const { body, validationResult } = require('express-validator');

app.post(
    '/user',
    // username precisa ser um e-mail
    body('username').isEmail(),
    // password precisa ter pelo menos 5 caracteres
    body('password').isLength({ min: 5 }),
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        User.create({
            username: req.body.username,
            password: req.body.password,
        }).then(user => res.json(user));
    }
); 

```

O ***Express-Validator*** também possibilita a sanitização dos dados da request, removendo caracteres que poderiam deixar o input vulnerável:

```js
const express = require('express');
const { body, validationResult } = require('express-validator');

const app = express();
app.use(express.json());

app.post(
    '/comment',
    body('email').isEmail().normalizeEmail(),
    body('text').not().isEmpty().trim().escape(),
    body('notifyOnReply').toBoolean(),
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        Comment.create({
          email: req.body.email,
          text: req.body.text,
          notifyOnReply: req.body.notifyOnReply,
        }).then(comment => res.json(comment));
        }
);
```

Você pode saber mais sobre os métodos de sanitização do ***Express-Validator*** [aqui](https://github.com/validatorjs/validator.js#sanitizers).

Utilizando essas ferramentas, garantimos que o input enviado na requisição seja de fato aquele que o servidor está preparado para receber. 

### Configuração segura de cabeçalhos HTTP:

Outro middleware do Express é o [Helmet](https://github.com/helmetjs/helmet/) que tem como objetivo inserir mais uma camada de segurança na aplicação com a configuração adequada de cabeçalhos. 

Utilização:

```js

const express = require('express');
const helmet = require('helmet');

const app = express();

app.use(helmet());

// ...

```

Algumas funções de middlewares do ***Helmet*** são importantes para combater a vulnerabilidade XSS como `helmet.contentSecurityPolicy(options)` que configura o cabeçalho ***Content-Security-Policy*** (CSP). Ele fornece uma lista de recursos confiáveis no qual o navegador pode confiar e, com isso, é possível impedir a execução de um código malicioso. 

Além dessa função, temos a `helmet.xssFilter()` que configura o ***X-XSS-Protection*** para ativar o filtro de Cross-site Scripting nos navegadores da web mais recentes.

### Opções de segurança de cookies:

Como o roubo de cookies é um dos mais comuns ataques XSS, uma boa maneira de mitigar esse risco é evitando que os cookies sejam acessados pelo browser com código JavaScript e somente através de requisição HTTP(S). Isso pode ser feito com as flags `httpOnly` e `secure` configuradas como `true`:

```js
app.use(express.session({
    secret: 'MY_SECRET',
    cookie: {
        httpOnly: true,
        secure: true
    }
})
);
```

É importante também não utilizar o cookie de sessão padrão e assegurar que o cookie tenha um tempo de expiração. O middleware  [cookie-session](https://www.npmjs.com/package/cookie-session) nos ajuda a configurar as opções de cookies:

```js
var session = require('cookie-session');
var express = require('express');
var app = express();

var expiryDate = new Date(Date.now() + 60 * 60 * 1000); // 1 hora
app.use(session({
    name: 'session',
    keys: ['key1', 'key2'],
    cookie: { 
        secure: true,
        httpOnly: true,
        domain: 'example.com',
        path: 'foo/bar',
        expires: expiryDate
    }
}));
```