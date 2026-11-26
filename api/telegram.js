import crypto from "crypto";
import { createClient } from "@supabase/supabase-js";

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const { initData } = req.body || {};

    if (!initData || !process.env.TELEGRAM_BOT_TOKEN) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const params = new URLSearchParams(initData);
    const hash = params.get("hash");
    params.delete("hash");

    const dataCheckString = [...params.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `${key}=${value}`)
      .join("\n");

    const secretKey = crypto
      .createHmac("sha256", "WebAppData")
      .update(process.env.TELEGRAM_BOT_TOKEN)
      .digest();

    const calculatedHash = crypto
      .createHmac("sha256", secretKey)
      .update(dataCheckString)
      .digest("hex");

    if (
      !hash ||
      !crypto.timingSafeEqual(
        Buffer.from(hash, "hex"),
        Buffer.from(calculatedHash, "hex")
      )
    ) {
      return res.status(401).json({ error: "Invalid Telegram data" });
    }

    const authDate = Number(params.get("auth_date"));
    if (!authDate || Date.now() / 1000 - authDate > 86400) {
      return res.status(401).json({ error: "Expired Telegram data" });
    }

    const user = JSON.parse(params.get("user") || "{}");
    if (!user.id) {
      return res.status(401).json({ error: "User not found" });
    }

    const supabase = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_SERVICE_ROLE_KEY
    );

    const { data, error } = await supabase
      .from("users")
      .upsert({
        telegram_id: String(user.id),
        username: user.username || null,
        first_name: user.first_name || null,
        last_name: user.last_name || null
      }, { onConflict: "telegram_id" })
      .select("telegram_id, username, first_name, last_name, points")
      .single();

    if (error) throw error;

    return res.status(200).json({ user: data });
  } catch (error) {
    console.error("Telegram API error:", error);
    return res.status(500).json({ error: "Server error" });
  }
}
