import { NextApiRequest, NextApiResponse } from "next";
import { resolvedConfig } from "../../utils.server";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if(!resolvedConfig.externalJwtAuthRedirectUrl) return res.status(400).json({error: "no redirect url"});
  if(!resolvedConfig.externalJwtAuthRedirectUrlParam) return res.status(400).json({error: "no redirect url param"});
  if(!req.headers.host) return res.status(400).json({error: "missing host header"});

  const callback = "https://" + req.headers.host + req.url;
  const u = new URL(resolvedConfig.externalJwtAuthRedirectUrl);
  u.searchParams.set(resolvedConfig.externalJwtAuthRedirectUrlParam, callback);
  res.redirect(302, u.toString());
}