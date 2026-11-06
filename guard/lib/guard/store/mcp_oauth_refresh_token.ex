defmodule Guard.Store.McpOAuthRefreshToken do
  @moduledoc """
  Store module for MCP OAuth refresh tokens. A token is looked up by its SHA-256
  and rotates within the family started by one authorization code.
  """

  import Ecto.Query

  alias Guard.Repo
  alias Guard.Repo.{McpOAuthRefreshToken, McpOAuthRefreshTokenFamily}

  @revoked_retention_seconds 86_400

  @doc "Starts a family of refresh tokens and returns its first token."
  @spec create(String.t(), String.t(), String.t()) :: String.t()
  def create(client_id, user_id, scope) do
    now = now()

    family =
      Repo.insert!(%McpOAuthRefreshTokenFamily{
        client_id: client_id,
        user_id: user_id,
        scope: scope,
        expires_at: DateTime.add(now, max_age_seconds())
      })

    insert_token(family, now)
  end

  @doc """
  Locks a token and its family, preloaded, using SELECT FOR UPDATE.
  Must be called inside a Repo.transaction.
  """
  @spec lock_by_token(String.t()) :: {:ok, McpOAuthRefreshToken.t()} | {:error, :not_found}
  def lock_by_token(token) when is_binary(token) do
    query =
      from(t in McpOAuthRefreshToken,
        join: f in assoc(t, :family),
        where: t.token_hash == ^hash(token),
        lock: "FOR UPDATE",
        preload: [family: f]
      )

    case Repo.one(query) do
      nil -> {:error, :not_found}
      refresh_token -> {:ok, refresh_token}
    end
  end

  @doc """
  Marks a locked token used, unless it already is, and returns the next token
  of its family.
  """
  @spec rotate(McpOAuthRefreshToken.t()) :: String.t()
  def rotate(%McpOAuthRefreshToken{} = refresh_token) do
    now = now()

    if is_nil(refresh_token.used_at) do
      refresh_token |> Ecto.Changeset.change(used_at: now) |> Repo.update!()
    end

    insert_token(refresh_token.family, now)
  end

  @spec revoke_family(McpOAuthRefreshTokenFamily.t()) :: McpOAuthRefreshTokenFamily.t()
  def revoke_family(%McpOAuthRefreshTokenFamily{} = family) do
    family |> Ecto.Changeset.change(revoked_at: now()) |> Repo.update!()
  end

  @doc """
  Deletes expired tokens, and expired families or ones revoked over a day ago
  along with their tokens. Returns the number of families and tokens deleted.
  """
  @spec cleanup_expired() :: {non_neg_integer(), non_neg_integer()}
  def cleanup_expired do
    now = now()
    revoked_before = DateTime.add(now, -@revoked_retention_seconds)

    {families, _} =
      McpOAuthRefreshTokenFamily
      |> where([f], f.expires_at < ^now or f.revoked_at < ^revoked_before)
      |> Repo.delete_all()

    {tokens, _} =
      McpOAuthRefreshToken
      |> where([t], t.expires_at < ^now)
      |> Repo.delete_all()

    {families, tokens}
  end

  defp insert_token(family, now) do
    token = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)

    Repo.insert!(%McpOAuthRefreshToken{
      family_id: family.id,
      token_hash: hash(token),
      expires_at: Enum.min([DateTime.add(now, ttl_seconds()), family.expires_at], DateTime)
    })

    token
  end

  defp hash(token), do: :crypto.hash(:sha256, token) |> Base.encode16(case: :lower)

  defp now, do: DateTime.utc_now() |> DateTime.truncate(:second)

  defp ttl_seconds, do: Application.fetch_env!(:guard, :mcp_oauth_refresh_token_ttl_seconds)

  defp max_age_seconds,
    do: Application.fetch_env!(:guard, :mcp_oauth_refresh_token_max_age_seconds)
end
