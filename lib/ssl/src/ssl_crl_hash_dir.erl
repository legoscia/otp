-module(ssl_crl_hash_dir).

-include_lib("public_key/include/public_key.hrl"). 

-behaviour(ssl_crl_cache_api).

-export([lookup/2, select/2, fresh_crl/2]).

lookup(#'DistributionPoint'{}, _CRLDbInfo) ->
    not_available.

fresh_crl(#'DistributionPoint'{}, CurrentCRL) ->
    CurrentCRL.

select(Issuer, {_DbHandle, [{dir, Dir}]}) ->
    Hash = public_key:openssl_name_hash(Issuer),
    case find_crl(Hash, Dir) of
        {ok, File} ->
            case read_crl_as_der(File) of
                {ok, CRL} ->
                    [CRL];
                {error, Error} ->
                    error_logger:error_report(
                      [{cannot_read_crl, Error},
                       {file, File},
                       {module, ?MODULE},
                       {line, ?LINE}]),
                    []
            end;
        {error, not_found} ->
            %% That's okay, just report that we didn't find any CRL.
            %% If the crl_check setting is best_effort, ssl_handshake
            %% is happy with that, but if it's true, this is an error.
            [];
        {error, Error} ->
            error_logger:error_report(
              [{cannot_find_crl, Error},
               {dir, Dir},
               {module, ?MODULE},
               {line, ?LINE}]),
            []
    end.

find_crl(Hash, Dir) ->
    case filelib:is_dir(Dir) of
        true ->
            find_crl(Hash, Dir, 0, {error, not_found});
        false ->
            {error, not_a_directory}
    end.

find_crl(Hash, Dir, N, RetIfNotFound) ->
    Filename = filename:join(Dir, Hash ++ ".r" ++ integer_to_list(N)),
    case filelib:is_file(Filename) of
        true ->
            NewRet = {ok, Filename},
            %% This file exists.  Now check if there is a file with a
            %% higher serial number.
            find_crl(Hash, Dir, N + 1, NewRet);
        false ->
            %% We've found the highest-numbered file (or no file at
            %% all, if N is 0).
            RetIfNotFound
    end.

read_crl_as_der(Filename) ->
    case file:read_file(Filename) of
        {error, Error} ->
            {error, Error};
        {ok, <<"-----BEGIN", _/binary>> = PEM} ->
            %% It's a PEM encoded file.  Need to extract the DER
            %% encoded data.
            [{'CertificateList', DER, not_encrypted}] = public_key:pem_decode(PEM),
            {ok, DER};
        {ok, ProbablyDER} ->
            %% It's probably a DER encoded file.  Return it as it is.
            {ok, ProbablyDER}
    end.
