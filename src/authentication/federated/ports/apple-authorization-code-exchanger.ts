export interface AppleAuthorizationCodeExchanger {
  exchange(authorizationCode: string): Promise<string>;
}
