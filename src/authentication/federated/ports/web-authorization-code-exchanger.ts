export interface WebAuthorizationCodeExchangeInput {
  readonly authorizationCode: string;
  readonly codeVerifier?: string;
}

export interface WebAuthorizationCodeExchanger {
  exchange(input: WebAuthorizationCodeExchangeInput): Promise<string>;
}
