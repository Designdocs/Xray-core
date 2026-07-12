package artx

import (
	"context"
	"errors"
	"strings"

	"github.com/xtls/xray-core/common/protocol"
)

func (s *Server) AddUser(_ context.Context, user *protocol.MemoryUser) error {
	if user == nil || user.Email == "" {
		return errors.New("artx: invalid user")
	}
	account, ok := user.Account.(*MemoryAccount)
	if !ok || strings.TrimSpace(account.PSK) == "" {
		return errors.New("artx: invalid account")
	}
	locator := CalculateUserLocator([]byte(account.PSK))

	s.userMu.Lock()
	defer s.userMu.Unlock()
	s.ensureUsers()
	if existing := s.users[locator]; existing != nil && existing.Email != user.Email {
		return errors.New("artx: user locator collision")
	}
	if previous, ok := s.locators[user.Email]; ok && previous != locator {
		delete(s.users, previous)
	}
	s.users[locator] = user
	s.locators[user.Email] = locator
	return nil
}

func (s *Server) RemoveUser(_ context.Context, email string) error {
	if email == "" {
		return errors.New("artx: empty email")
	}
	s.userMu.Lock()
	defer s.userMu.Unlock()
	s.ensureUsers()
	if locator, ok := s.locators[email]; ok {
		delete(s.locators, email)
		delete(s.users, locator)
	}
	return nil
}

func (s *Server) GetUser(_ context.Context, email string) *protocol.MemoryUser {
	s.userMu.RLock()
	defer s.userMu.RUnlock()
	locator, ok := s.locators[email]
	if !ok {
		return nil
	}
	return s.users[locator]
}

func (s *Server) GetUsers(_ context.Context) []*protocol.MemoryUser {
	s.userMu.RLock()
	defer s.userMu.RUnlock()
	users := make([]*protocol.MemoryUser, 0, len(s.users))
	for _, user := range s.users {
		users = append(users, user)
	}
	return users
}

func (s *Server) GetUsersCount(context.Context) int64 {
	s.userMu.RLock()
	defer s.userMu.RUnlock()
	return int64(len(s.users))
}

func (s *Server) userByLocator(locator [UserLocatorLength]byte) *protocol.MemoryUser {
	s.userMu.RLock()
	defer s.userMu.RUnlock()
	return s.users[locator]
}

func (s *Server) ensureUsers() {
	if s.users == nil {
		s.users = make(map[[UserLocatorLength]byte]*protocol.MemoryUser)
		s.locators = make(map[string][UserLocatorLength]byte)
	}
}
