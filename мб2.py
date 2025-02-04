import pygame
import random
import copy
import requests
from tkinter import Tk, Label, Entry, Button as TkButton, messagebox

class LoginWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Вход в игру")
        self.root.geometry("400x350")

        Label(root, text="Логин", font=('Arial', 14)).pack(pady=5)
        self.username = Entry(root, font=('Arial', 12))
        self.username.pack(pady=5)

        Label(root, text="Пароль", font=('Arial', 14)).pack(pady=5)
        self.password = Entry(root, show="*", font=('Arial', 12))
        self.password.pack(pady=5)

        TkButton(root, text="Войти", command=self.login, font=('Arial', 12)).pack(pady=10)
        TkButton(root, text="Зарегистрироваться", command=self.open_register, font=('Arial', 12)).pack(pady=5)
        TkButton(root, text="Сменить пароль", command=self.open_change_password_window, font=('Arial', 12)).pack(pady=5)
        TkButton(root, text="Удалить пользователя", command=self.delete_user, font=('Arial', 12)).pack(pady=5)

    def login(self):
        username = self.username.get().strip()
        password = self.password.get().strip()

        if not username or not password:
            messagebox.showerror("Ошибка", "Введите логин и пароль")
            return

        try:
            response = requests.post(
                "http://127.0.0.1:8000/login",
                json={"username": username, "password": password}
            )

            if response.status_code == 200:
                user_data = response.json()
                self.token = user_data['token']
                self.user_id = user_data['id']

                messagebox.showinfo("Успех", "Вы успешно вошли!")
                self.root.destroy()
                main(self.token, self.user_id)

            else:
                messagebox.showerror("Ошибка", response.json().get("detail", "Ошибка авторизации"))
        except requests.RequestException as e:
            messagebox.showerror("Ошибка", f"Ошибка подключения: {e}")

    def delete_user(self):
        username = self.username.get().strip()
        password = self.password.get().strip()

        if not username or not password:
            messagebox.showerror("Ошибка", "Введите логин и пароль.")
            return

        confirmation = messagebox.askyesno("Подтверждение", f"Вы уверены, что хотите удалить пользователя {username}?")
        if not confirmation:
            return

        try:
            response = requests.delete(
                f"http://127.0.0.1:8000/delete_user/{username}",
                json={"password": password}
            )

            if response.status_code == 200:
                messagebox.showinfo("Успех", "Пользователь успешно удален.")
                self.root.destroy()  # Закрываем окно после удаления
            else:
                error_message = response.json().get("detail", "Ошибка удаления пользователя")
                messagebox.showerror("Ошибка", error_message)
        except requests.RequestException as e:
            messagebox.showerror("Ошибка", f"Ошибка подключения: {e}")

    def open_register(self):
        self.root.destroy()
        root = Tk()
        RegisterWindow(root)
        root.mainloop()

    def open_change_password_window(self):
        self.change_password_window = ChangePasswordWindow(self.root)  # Передаем root

class RegisterWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Регистрация")
        self.root.geometry("300x300")

        Label(root, text="Регистрация", font=('Arial', 16)).pack(pady=10)
        Label(root, text="Логин", font=('Arial', 14)).pack(pady=5)
        self.username = Entry(root, font=('Arial', 12))
        self.username.pack(pady=5)

        Label(root, text="Пароль", font=('Arial', 14)).pack(pady=5)
        self.password = Entry(root, show="*", font=('Arial', 12))
        self.password.pack(pady=5)

        TkButton(root, text="Зарегистрироваться", command=self.register, font=('Arial', 12)).pack(pady=10)
        TkButton(root, text="Назад", command=self.go_back, font=('Arial', 12)).pack(pady=5)

    def register(self):
        username = self.username.get()
        password = self.password.get()

        if not username or not password:
            messagebox.showerror("Ошибка", "Введите логин и пароль")
            return

        try:
            response = requests.post(
                "http://127.0.0.1:8000/register",
                json={"username": username, "password": password}
            )
            response.raise_for_status()  # Проверяем статус ответа

            if response.status_code == 200:
                messagebox.showinfo("Успех", "Регистрация прошла успешно!")
                self.go_back()
            else:
                messagebox.showerror("Ошибка", response.json().get("detail", "Ошибка регистрации"))
        except requests.RequestException as e:
            messagebox.showerror("Ошибка", f"Ошибка подключения: {str(e)}")

    def go_back(self):
        self.root.destroy()
        root = Tk()
        LoginWindow(root)
        root.mainloop()

class ChangePasswordWindow:
    def __init__(self, root, token, user_id):
        self.root = root
        self.token = token
        self.user_id = user_id
        self.root.title("Смена пароля")
        self.root.geometry("300x250")

        Label(root, text="Старый пароль", font=('Arial', 14)).pack(pady=5)
        self.old_password = Entry(root, show="*", font=('Arial', 12))
        self.old_password.pack(pady=5)

        Label(root, text="Новый пароль", font=('Arial', 14)).pack(pady=5)
        self.new_password = Entry(root, show="*", font=('Arial', 12))
        self.new_password.pack(pady=5)

        TkButton(root, text="Изменить пароль", command=self.change_password, font=('Arial', 12)).pack(pady=10)
        TkButton(root, text="Назад", command=self.go_back, font=('Arial', 12)).pack(pady=5)

    def change_password(self):
        old_password = self.old_password.get()
        new_password = self.new_password.get()

        if not old_password or not new_password:
            messagebox.showerror("Ошибка", "Введите старый и новый пароль")
            return

        try:
            response = requests.post(
                "http://127.0.0.1:8000/change_password",
                json={"username": self.user_id, "old_password": old_password, "new_password": new_password}
            )

            if response.status_code == 200:
                messagebox.showinfo("Успех", "Пароль успешно изменен!")
                self.go_back()
            else:
                messagebox.showerror("Ошибка", response.json().get("detail", "Ошибка изменения пароля"))
        except requests.RequestException as e:
            messagebox.showerror("Ошибка", f"Ошибка подключения: {e}")

    def go_back(self):
        self.root.destroy()
        root = Tk()
        UserSettingsWindow(root, self.token, self.user_id)
        root.mainloop()

class DeleteUserWindow:
    def __init__(self, root, token, user_id):
        self.root = root
        self.token = token
        self.user_id = user_id
        self.root.title("Удаление пользователя")
        self.root.geometry("300x250")

        Label(root, text="Пароль", font=('Arial', 14)).pack(pady=5)
        self.password = Entry(root, show="*", font=('Arial', 12))
        self.password.pack(pady=5)

        TkButton(root, text="Удалить аккаунт", command=self.delete_account, font=('Arial', 12)).pack(pady=10)
        TkButton(root, text="Назад", command=self.go_back, font=('Arial', 12)).pack(pady=5)

    def delete_account(self):
        password = self.password.get()

        if not password:
            messagebox.showerror("Ошибка", "Введите пароль")
            return

        try:
            response = requests.post(
                "http://127.0.0.1:8000/delete_user",
                json={"username": self.user_id, "password": password}
            )

            if response.status_code == 200:
                messagebox.showinfo("Успех", "Аккаунт успешно удален!")
                self.root.destroy()
                root = Tk()
                LoginWindow(root)
                root.mainloop()
            else:
                messagebox.showerror("Ошибка", response.json().get("detail", "Ошибка удаления аккаунта"))
        except requests.RequestException as e:
            messagebox.showerror("Ошибка", f"Ошибка подключения: {e}")

    def go_back(self):
        self.root.destroy()
        root = Tk()
        UserSettingsWindow(root, self.token, self.user_id)
        root.mainloop()

class UserSettingsWindow:
    def __init__(self, root, token, user_id):
        self.root = root
        self.token = token
        self.user_id = user_id
        self.root.title("Настройки пользователя")
        self.root.geometry("300x200")

        TkButton(root, text="Сменить пароль", command=self.open_change_password, font=('Arial', 12)).pack(pady=10)
        TkButton(root, text="Удалить аккаунт", command=self.open_delete_account, font=('Arial', 12)).pack(pady=10)
        TkButton(root, text="Назад", command=self.go_back, font=('Arial', 12)).pack(pady=10)

    def open_change_password(self):
        self.root.destroy()
        root = Tk()
        ChangePasswordWindow(root, self.token, self.user_id)
        root.mainloop()

    def open_delete_account(self):
        self.root.destroy()
        root = Tk()
        DeleteUserWindow(root, self.token, self.user_id)
        root.mainloop()

    def go_back(self):
        self.root.destroy()
        root = Tk()
        LoginWindow(root)
        root.mainloop()

# -------------------- Игровая часть ------------------------

WHITE = (255, 255, 255)
BLACK = (0, 0, 0)
GREEN_BLUE = (0, 153, 153)
LIGHT_GRAY = (192, 192, 192)
RED = (255, 0, 0)

block_size = 50
left_margin = 5 * block_size
upper_margin = 2 * block_size
size = (left_margin + 30 * block_size, upper_margin + 15 * block_size)
LETTERS = "АБВГДЕЖЗИК"

pygame.init()

screen = pygame.display.set_mode(size)
pygame.display.set_caption("МОРСКОЙ БОЙ")
font_size = int(block_size / 1.5)
font = pygame.font.SysFont('notosans', font_size)
game_over_font_size = 3 * block_size
game_over_font = pygame.font.SysFont('notosans', game_over_font_size)

# COMPUTER DATA
computer_available_to_fire_set = {(x, y) for x in range(16, 26) for y in range(1, 11)}
around_last_computer_hit_set = set()
dotted_set_for_computer_not_to_shoot = set()
hit_blocks_for_computer_not_to_shoot = set()
last_hits_list = []

hit_blocks = set()
dotted_set = set()
destroyed_computer_ships = []

class Grid:
    def __init__(self, title, offset):
        self.title = title
        self.offset = offset
        self.__draw_grid()
        self.__add_nums_letters_to_grid()
        self.__sign_grid()

    def __draw_grid(self):
        for i in range(11):
            # Horizontal lines
            pygame.draw.line(screen, BLACK, (left_margin + self.offset * block_size, upper_margin + i * block_size),
                             (left_margin + (10 + self.offset) * block_size, upper_margin + i * block_size), 1)
            # Vertical lines
            pygame.draw.line(screen, BLACK, (left_margin + (i + self.offset) * block_size, upper_margin),
                             (left_margin + (i + self.offset) * block_size, upper_margin + 10 * block_size), 1)

    def __add_nums_letters_to_grid(self):
        for i in range(10):
            num_ver = font.render(str(i + 1), True, BLACK)
            letters_hor = font.render(LETTERS[i], True, BLACK)
            num_ver_width = num_ver.get_width()
            num_ver_height = num_ver.get_height()
            letters_hor_width = letters_hor.get_width()

            # Numbers (vertical)
            screen.blit(num_ver, (left_margin - (block_size // 2 + num_ver_width // 2) + self.offset * block_size,
                                  upper_margin + i * block_size + (block_size // 2 - num_ver_height // 2)))
            # Letters (horizontal)
            screen.blit(letters_hor, (left_margin + i * block_size + (block_size // 2 - letters_hor_width // 2) + self.offset * block_size,
                                     upper_margin + 10 * block_size))

    def __sign_grid(self):
        player = font.render(self.title, True, BLACK)
        sign_width = player.get_width()
        screen.blit(player, (left_margin + 5 * block_size - sign_width // 2 + self.offset * block_size,
                             upper_margin - block_size // 2 - font_size))

class CustomButton:
    def __init__(self, x_offset, button_title, message_to_show):
        self.__title = button_title
        self.__title_width, self.__title_height = font.size(self.__title)
        self.__message = message_to_show
        self.__button_width = self.__title_width + block_size
        self.__button_height = self.__title_height + block_size
        self.__x_start = x_offset
        self.__y_start = upper_margin + 10 * block_size + self.__button_height
        self.rect_for_draw = self.__x_start, self.__y_start, self.__button_width, self.__button_height
        self.rect = pygame.Rect(self.rect_for_draw)
        self.__rect_for_button_title = self.__x_start + self.__button_width / 2 - self.__title_width / 2, \
            self.__y_start + self.__button_height / 2 - self.__title_height / 2
        self.__color = BLACK

    def draw_button(self, color=None):
        if not color:
            color = self.__color
        pygame.draw.rect(screen, color, self.rect_for_draw)
        text_to_blit = font.render(self.__title, True, WHITE)
        screen.blit(text_to_blit, self.__rect_for_button_title)

    def change_color_on_hover(self):
        mouse = pygame.mouse.get_pos()
        if self.rect.collidepoint(mouse):
            self.draw_button(GREEN_BLUE)

    def print_message_for_button(self):
        message_width, message_height = font.size(self.__message)
        rect_for_message = self.__x_start / 2 - message_width / 2, \
            self.__y_start + self.__button_height / 2 - message_height / 2
        text = font.render(self.__message, True, BLACK)
        screen.blit(text, rect_for_message)

class AutoShips:
    def __init__(self, offset):
        self.offset = offset
        self.available_blocks = {(x, y) for x in range(1 + self.offset, 11 + self.offset) for y in range(1, 11)}
        self.ships_set = set()
        self.ships = self.__populate_grid()
        self.orientation = None
        self.direction = None

    def __create_start_block(self, available_blocks):
        self.orientation = random.randint(0, 1)
        self.direction = random.choice((-1, 1))
        x, y = random.choice(tuple(available_blocks))
        return x, y, self.orientation, self.direction

    def __create_ship(self, number_of_blocks, available_blocks):
        ship_coordinates = []
        x, y, self.orientation, self.direction = self.__create_start_block(available_blocks)
        for _ in range(number_of_blocks):
            ship_coordinates.append((x, y))
            if not self.orientation:
                self.direction, x = self.__get_new_block_for_ship(x, self.direction, self.orientation, ship_coordinates)
            else:
                self.direction, y = self.__get_new_block_for_ship(y, self.direction, self.orientation, ship_coordinates)
        if self.__is_ship_valid(ship_coordinates):
            return ship_coordinates
        return self.__create_ship(number_of_blocks, available_blocks)

    def __get_new_block_for_ship(self, coor, direction, orientation, ship_coordinates):
        self.direction = direction
        self.orientation = orientation
        if (coor <= 1 - self.offset * (self.orientation - 1) and self.direction == -1) or \
                (coor >= 10 - self.offset * (self.orientation - 1) and self.direction == 1):
            self.direction *= -1
            return self.direction, ship_coordinates[0][self.orientation] + self.direction
        else:
            return self.direction, ship_coordinates[-1][self.orientation] + self.direction

    def __is_ship_valid(self, new_ship):
        ship = set(new_ship)
        return ship.issubset(self.available_blocks)

    def __add_new_ship_to_set(self, new_ship):
        self.ships_set.update(new_ship)

    def __update_available_blocks_for_creating_ships(self, new_ship):
        for elem in new_ship:
            for k in range(-1, 2):
                for m in range(-1, 2):
                    if self.offset < (elem[0] + k) < 11 + self.offset and 0 < (elem[1] + m) < 11:
                        self.available_blocks.discard((elem[0] + k, elem[1] + m))

    def __populate_grid(self):
        ships_coordinates_list = []
        for number_of_blocks in range(4, 0, -1):
            for _ in range(5 - number_of_blocks):
                new_ship = self.__create_ship(number_of_blocks, self.available_blocks)
                ships_coordinates_list.append(new_ship)
                self.__add_new_ship_to_set(new_ship)
                self.__update_available_blocks_for_creating_ships(new_ship)
        return ships_coordinates_list


def computer_shoots(set_to_shoot_from):
    if not set_to_shoot_from:  # Проверяем, есть ли доступные клетки
        return None

    pygame.time.delay(500)
    computer_fired_block = random.choice(tuple(set_to_shoot_from))
    set_to_shoot_from.discard(computer_fired_block)
    return computer_fired_block

def check_hit_or_miss(fired_block, opponents_ships_list, computer_turn, opponents_ships_list_original_copy, opponents_ships_set):
    for elem in opponents_ships_list:
        diagonal_only = True
        if fired_block in elem:
            ind = opponents_ships_list.index(elem)
            if len(elem) == 1:
                diagonal_only = False
            update_dotted_and_hit_sets(fired_block, computer_turn, diagonal_only)
            elem.remove(fired_block)
            opponents_ships_set.discard(fired_block)
            if computer_turn:
                last_hits_list.append(fired_block)
                update_around_last_computer_hit(fired_block, True)
            if not elem:
                update_destroyed_ships(ind, computer_turn, opponents_ships_list_original_copy)
                if computer_turn:
                    last_hits_list.clear()
                    around_last_computer_hit_set.clear()
                else:
                    destroyed_computer_ships.append(computer.ships[ind])
            return True
    add_missed_block_to_dotted_set(fired_block)
    if computer_turn:
        update_around_last_computer_hit(fired_block, False)
    return False

def update_destroyed_ships(ind, computer_turn, opponents_ships_list_original_copy):
    ship = sorted(opponents_ships_list_original_copy[ind])
    for i in range(-1, 1):
        update_dotted_and_hit_sets(ship[i], computer_turn, False)

def update_around_last_computer_hit(fired_block, computer_hits):
    global around_last_computer_hit_set, computer_available_to_fire_set
    if computer_hits and fired_block in around_last_computer_hit_set:
        around_last_computer_hit_set = computer_hits_twice()
    elif computer_hits and fired_block not in around_last_computer_hit_set:
        computer_first_hit(fired_block)
    elif not computer_hits:
        around_last_computer_hit_set.discard(fired_block)

    around_last_computer_hit_set -= dotted_set_for_computer_not_to_shoot
    around_last_computer_hit_set -= hit_blocks_for_computer_not_to_shoot
    computer_available_to_fire_set -= around_last_computer_hit_set
    computer_available_to_fire_set -= dotted_set_for_computer_not_to_shoot

def computer_first_hit(fired_block):
    x_hit, y_hit = fired_block
    if x_hit > 16:
        around_last_computer_hit_set.add((x_hit - 1, y_hit))
    if x_hit < 25:
        around_last_computer_hit_set.add((x_hit + 1, y_hit))
    if y_hit > 1:
        around_last_computer_hit_set.add((x_hit, y_hit - 1))
    if y_hit < 10:
        around_last_computer_hit_set.add((x_hit, y_hit + 1))

def computer_hits_twice():
    last_hits_list.sort()
    new_around_last_hit_set = set()
    for i in range(len(last_hits_list) - 1):
        x1 = last_hits_list[i][0]
        x2 = last_hits_list[i + 1][0]
        y1 = last_hits_list[i][1]
        y2 = last_hits_list[i + 1][1]
        if x1 == x2:
            if y1 > 1:
                new_around_last_hit_set.add((x1, y1 - 1))
            if y2 < 10:
                new_around_last_hit_set.add((x1, y2 + 1))
        elif y1 == y2:
            if x1 > 16:
                new_around_last_hit_set.add((x1 - 1, y1))
            if x2 < 25:
                new_around_last_hit_set.add((x2 + 1, y1))
    return new_around_last_hit_set

def update_dotted_and_hit_sets(fired_block, computer_turn, diagonal_only=True):
    global dotted_set
    x, y = fired_block
    a = 15 * computer_turn
    b = 11 + 15 * computer_turn
    hit_blocks_for_computer_not_to_shoot.add(fired_block)
    hit_blocks.add(fired_block)
    for i in range(-1, 2):
        for j in range(-1, 2):
            if (not diagonal_only or i != 0 and j != 0) and a < x + i < b and 0 < y + j < 11:
                add_missed_block_to_dotted_set((x + i, y + j))
    dotted_set -= hit_blocks

def add_missed_block_to_dotted_set(fired_block):
    dotted_set.add(fired_block)
    dotted_set_for_computer_not_to_shoot.add(fired_block)

def draw_ships(ships_coordinates_list):
    for elem in ships_coordinates_list:
        ship = sorted(elem)
        x_start = ship[0][0]
        y_start = ship[0][1]
        ship_width = block_size * len(ship)
        ship_height = block_size
        if len(ship) > 1 and ship[0][0] == ship[1][0]:
            ship_width, ship_height = ship_height, ship_width
        x = block_size * (x_start - 1) + left_margin
        y = block_size * (y_start - 1) + upper_margin
        pygame.draw.rect(screen, BLACK, ((x, y), (ship_width, ship_height)), width=block_size // 10)

def draw_from_dotted_set(dotted_set_to_draw_from):
    for elem in dotted_set_to_draw_from:
        pygame.draw.circle(screen, BLACK, (block_size * (elem[0] - 0.5) + left_margin,
                                         block_size * (elem[1] - 0.5) + upper_margin), block_size // 6)

def draw_hit_blocks(hit_blocks_to_draw_from):
    for block in hit_blocks_to_draw_from:
        x1 = block_size * (block[0] - 1) + left_margin
        y1 = block_size * (block[1] - 1) + upper_margin
        pygame.draw.line(screen, BLACK, (x1, y1),
                         (x1 + block_size, y1 + block_size), block_size // 6)
        pygame.draw.line(screen, BLACK, (x1, y1 + block_size),
                         (x1 + block_size, y1), block_size // 6)


def show_message_at_rect_center(message, rect, which_font=font, color=RED):
    # Преобразуем кортеж в Rect, если это необходимо
    if isinstance(rect, tuple) and len(rect) == 4:
        message_rect = pygame.Rect(rect)
    else:
        message_rect = rect  # rect уже является Rect объектом

    message_width, message_height = which_font.size(message)
    x_start = message_rect.centerx - message_width / 2
    y_start = message_rect.centery - message_height / 2
    background_rect = pygame.Rect(
        x_start - block_size / 2,
        y_start,
        message_width + block_size,
        message_height
    )

    message_to_blit = which_font.render(message, True, color)
    screen.fill(WHITE, background_rect)
    screen.blit(message_to_blit, (x_start, y_start))

def ship_is_valid(ship_set, blocks_for_manual_drawing):
    return ship_set.isdisjoint(blocks_for_manual_drawing)

def check_ships_numbers(ship, num_ships_list):
    return (5 - len(ship)) > num_ships_list[len(ship) - 1]

def update_used_blocks(ship, method):
    for block in ship:
        for i in range(-1, 2):
            for j in range(-1, 2):
                method((block[0]+i, block[1]+j))

computer = AutoShips(0)
computer_ships_working = copy.deepcopy(computer.ships)

auto_button_place = left_margin + 17 * block_size
manual_button_place = left_margin + 20 * block_size
how_to_create_ships_message = "Как вы хотите создать корабли? Нажмите кнопку"
auto_button = CustomButton(auto_button_place, "АВТО", how_to_create_ships_message)
manual_button = CustomButton(manual_button_place, "ВРУЧНУЮ", how_to_create_ships_message)
undo_message = "Для отмены последнего корабля нажмите кнопку"
undo_button_place = left_margin + 12 * block_size
undo_button = CustomButton(undo_button_place, "ОТМЕНА", undo_message)

def main(token=None, user_id=None):
    ships_creation_not_decided = True
    ships_not_created = True
    drawing = False
    game_over = False
    computer_turn = False
    start = (0, 0)
    ship_size = (0, 0)
    score = 0
    best_score = 0

    rect_for_grids = (0, 0, size[0], upper_margin + 12 * block_size)
    rect_for_messages_and_buttons = (0, upper_margin + 11 * block_size, size[0], 5 * block_size)
    message_rect_for_drawing_ships = (undo_button.rect_for_draw[0] + undo_button.rect_for_draw[2],
                                    upper_margin + 11 * block_size,
                                    size[0]-(undo_button.rect_for_draw[0] + undo_button.rect_for_draw[2]),
                                    4 * block_size)
    message_rect_computer = (left_margin - 2 * block_size, upper_margin + 11 * block_size,
                           14 * block_size, 4 * block_size)
    message_rect_human = (left_margin + 15 * block_size, upper_margin + 11 * block_size,
                         10 * block_size, 4 * block_size)

    human_ships_to_draw = []
    human_ships_set = set()
    used_blocks_for_manual_drawing = set()
    num_ships_list = [0, 0, 0, 0]

    screen.fill(WHITE)
    computer_grid = Grid("КОМПЬЮТЕР", 0)
    human_grid = Grid("ЧЕЛОВЕК", 15)

    while ships_creation_not_decided:
        auto_button.draw_button()
        manual_button.draw_button()
        auto_button.change_color_on_hover()
        manual_button.change_color_on_hover()
        auto_button.print_message_for_button()

        mouse = pygame.mouse.get_pos()
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                game_over = True
                ships_creation_not_decided = False
                ships_not_created = False
            elif event.type == pygame.MOUSEBUTTONDOWN and auto_button.rect.collidepoint(mouse):
                print("Clicked AUTO!", event.pos)
                human = AutoShips(15)
                human_ships_to_draw = human.ships
                human_ships_working = copy.deepcopy(human.ships)
                human_ships_set = human.ships_set
                ships_creation_not_decided = False
                ships_not_created = False
            elif event.type == pygame.MOUSEBUTTONDOWN and manual_button.rect.collidepoint(mouse):
                ships_creation_not_decided = False

        pygame.display.update()
        screen.fill(WHITE, rect_for_messages_and_buttons)

    while ships_not_created:
        screen.fill(WHITE, rect_for_grids)
        computer_grid = Grid("КОМПЬЮТЕР", 0)
        human_grid = Grid("ЧЕЛОВЕК", 15)
        undo_button.draw_button()
        undo_button.print_message_for_button()
        undo_button.change_color_on_hover()
        mouse = pygame.mouse.get_pos()
        if not human_ships_to_draw:
            undo_button.draw_button(LIGHT_GRAY)
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                ships_not_created = False
                game_over = True
            elif undo_button.rect.collidepoint(mouse) and event.type == pygame.MOUSEBUTTONDOWN:
                if human_ships_to_draw:
                    screen.fill(WHITE, message_rect_for_drawing_ships)
                    deleted_ship = human_ships_to_draw.pop()
                    num_ships_list[len(deleted_ship) - 1] -= 1
                    update_used_blocks(deleted_ship, used_blocks_for_manual_drawing.discard)
            elif event.type == pygame.MOUSEBUTTONDOWN:
                drawing = True
                x_start, y_start = event.pos
                start = x_start, y_start
                ship_size = (0, 0)
            elif drawing and event.type == pygame.MOUSEMOTION:
                x_end, y_end = event.pos
                end = x_end, y_end
                ship_size = x_end - x_start, y_end - y_start
            elif drawing and event.type == pygame.MOUSEBUTTONUP:
                x_end, y_end = event.pos
                drawing = False
                ship_size = (0, 0)
                start_block = ((x_start - left_margin) // block_size + 1,
                               (y_start - upper_margin) // block_size + 1)
                end_block = ((x_end - left_margin) // block_size + 1,
                             (y_end - upper_margin) // block_size + 1)
                if start_block > end_block:
                    start_block, end_block = end_block, start_block
                temp_ship = []
                if 15 < start_block[0] < 26 and 0 < start_block[1] < 11 and 15 < end_block[0] < 26 and 0 < end_block[1] < 11:
                    screen.fill(WHITE, message_rect_for_drawing_ships)
                    if start_block[0] == end_block[0] and (end_block[1] - start_block[1]) < 4:
                        for block in range(start_block[1], end_block[1]+1):
                            temp_ship.append((start_block[0], block))
                    elif start_block[1] == end_block[1] and (end_block[0] - start_block[0]) < 4:
                        for block in range(start_block[0], end_block[0]+1):
                            temp_ship.append((block, start_block[1]))
                    else:
                        show_message_at_rect_center("КОРАБЛЬ СЛИШКОМ БОЛЬШОЙ!", message_rect_for_drawing_ships)
                else:
                    show_message_at_rect_center("КОРАБЛЬ ЗА ПРЕДЕЛАМИ СЕТКИ!", message_rect_for_drawing_ships)
                if temp_ship:
                    temp_ship_set = set(temp_ship)
                    if ship_is_valid(temp_ship_set, used_blocks_for_manual_drawing):
                        if check_ships_numbers(temp_ship, num_ships_list):
                            num_ships_list[len(temp_ship) - 1] += 1
                            human_ships_to_draw.append(temp_ship)
                            human_ships_set |= temp_ship_set
                            update_used_blocks(temp_ship, used_blocks_for_manual_drawing.add)
                        else:
                            show_message_at_rect_center(f"УЖЕ ДОСТАТОЧНО {len(temp_ship)}-ПАЛУБНЫХ КОРАБЛЕЙ", message_rect_for_drawing_ships)
                    else:
                        show_message_at_rect_center("КОРАБЛИ ПРИКАСАЮТСЯ!", message_rect_for_drawing_ships)
            if len(human_ships_to_draw) == 10:
                ships_not_created = False
                human_ships_working = copy.deepcopy(human_ships_to_draw)
                screen.fill(WHITE, rect_for_messages_and_buttons)

        pygame.draw.rect(screen, BLACK, (start, ship_size), 3)
        draw_ships(human_ships_to_draw)
        pygame.display.update()

    while not game_over:
        draw_ships(destroyed_computer_ships)
        draw_ships(human_ships_to_draw)
        if not (dotted_set | hit_blocks):
            show_message_at_rect_center("ИГРА НАЧАЛАСЬ! ВАШ ХОД!", message_rect_computer)
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                game_over = True
            elif not computer_turn and event.type == pygame.MOUSEBUTTONDOWN:
                x, y = event.pos
                if (left_margin < x < left_margin + 10 * block_size) and (upper_margin < y < upper_margin + 10 * block_size):
                    fired_block = ((x - left_margin) // block_size + 1, (y - upper_margin) // block_size + 1)
                    hit = check_hit_or_miss(fired_block, computer_ships_working, False, computer.ships, computer.ships_set)
                    if hit:
                        score += 10
                    computer_turn = not hit
                    draw_from_dotted_set(dotted_set)
                    draw_hit_blocks(hit_blocks)
                    screen.fill(WHITE, message_rect_computer)
                    show_message_at_rect_center(f"Ваш последний ход: {LETTERS[fired_block[0]-1] + str(fired_block[1])}",
                                              message_rect_computer, color=BLACK)
                else:
                    show_message_at_rect_center("ВЫСТРЕЛ ЗА ПРЕДЕЛАМИ СЕТКИ!", message_rect_computer)
        if computer_turn:
            set_to_shoot_from = computer_available_to_fire_set
            if around_last_computer_hit_set:
                set_to_shoot_from = around_last_computer_hit_set
            fired_block = computer_shoots(set_to_shoot_from)
            computer_turn = check_hit_or_miss(fired_block, human_ships_working, True, human_ships_to_draw, human_ships_set)
        draw_from_dotted_set(dotted_set)
        draw_hit_blocks(hit_blocks)
        screen.fill(WHITE, message_rect_human)

        if not computer.ships_set:
            show_message_at_rect_center("ВЫ ВЫИГРАЛИ!", (0, 0, size[0], size[1]), game_over_font)
            if score > best_score:
                best_score = score
                save_best_score(score, user_id)
        if not human_ships_set:
            show_message_at_rect_center("ВЫ ПРОИГРАЛИ!", (0, 0, size[0], size[1]), game_over_font)

        show_message_at_rect_center(f"Счёт: {score} | Лучший счёт: {best_score}",
                                    pygame.Rect(left_margin, upper_margin - 2 * block_size, 0, 0))

        pygame.display.update()

if __name__ == "__main__":
    root = Tk()
    LoginWindow(root)
    root.mainloop()