package examples

import (
	"context"
	"fmt"

	"github.com/ego-component/eoauth2/server"
)

type TestStorage struct {
	clients   map[string]server.Client
	authorize map[string]*server.AuthorizeData
	access    map[string]*server.AccessData
	refresh   map[string]string
}

var _ server.Storage = &TestStorage{}

func NewTestStorage() *TestStorage {
	r := &TestStorage{
		clients:   make(map[string]server.Client),
		authorize: make(map[string]*server.AuthorizeData),
		access:    make(map[string]*server.AccessData),
		refresh:   make(map[string]string),
	}

	r.clients["1234"] = &server.DefaultClient{
		Id:          "1234",
		Secret:      "aabbccdd",
		RedirectUri: "http://localhost:9090/appauth",
	}

	return r
}

func (s *TestStorage) Clone() server.Storage {
	return s
}

func (s *TestStorage) Close() {
}

func (s *TestStorage) GetClient(ctx context.Context, id string) (server.Client, error) {
	fmt.Printf("GetClient: %s\n", id)
	if c, ok := s.clients[id]; ok {
		return c, nil
	}
	return nil, server.ErrNotFound
}

func (s *TestStorage) SetClient(id string, client server.Client) error {
	fmt.Printf("SetClient: %s\n", id)
	s.clients[id] = client
	return nil
}

func (s *TestStorage) SaveAuthorize(ctx context.Context, data *server.AuthorizeData) error {
	fmt.Printf("SaveAuthorize: %s\n", data.Code)
	s.authorize[data.Code] = data
	return nil
}

func (s *TestStorage) LoadAuthorize(ctx context.Context, code string) (*server.AuthorizeData, error) {
	fmt.Printf("LoadAuthorize: %s\n", code)
	if d, ok := s.authorize[code]; ok {
		return d, nil
	}
	return nil, fmt.Errorf("LoadAuthorize not found")

}

func (s *TestStorage) RemoveAuthorize(ctx context.Context, code string) error {
	fmt.Printf("RemoveAuthorize: %s\n", code)
	delete(s.authorize, code)
	return nil
}

func (s *TestStorage) SaveAccess(ctx context.Context, data *server.AccessData) error {
	fmt.Printf("SaveAccess: %s\n", data.AccessToken)
	s.access[data.AccessToken] = data
	if data.RefreshToken != "" {
		s.refresh[data.RefreshToken] = data.AccessToken
	}
	return nil
}

func (s *TestStorage) LoadAccess(ctx context.Context, code string) (*server.AccessData, error) {
	fmt.Printf("LoadAccess: %s\n", code)
	if d, ok := s.access[code]; ok {
		return d, nil
	}
	return nil, fmt.Errorf("LoadAccess not found")
}

func (s *TestStorage) RemoveAccess(ctx context.Context, code string) error {
	fmt.Printf("RemoveAccess: %s\n", code)
	delete(s.access, code)
	return nil
}

func (s *TestStorage) LoadRefresh(ctx context.Context, code string) (*server.AccessData, error) {
	fmt.Printf("LoadRefresh: %s\n", code)
	if d, ok := s.refresh[code]; ok {
		return s.LoadAccess(ctx, d)
	}
	return nil, fmt.Errorf("LoadRefresh not found")

}

func (s *TestStorage) RemoveRefresh(ctx context.Context, code string) error {
	fmt.Printf("RemoveRefresh: %s\n", code)
	delete(s.refresh, code)
	return nil
}
