require("dotenv").config();
const axios = require("axios");

async function testWebhook() {
  const url = process.env.DISCORD_WEBHOOK_URL;

  const content =
    "🔔 **Test BeefMusic**\n" +
    "Si ves este mensaje, el webhook está funcionando.";

  await axios.post(url, { content });
  console.log("Mensaje de prueba enviado");
}

testWebhook().catch(console.error);
